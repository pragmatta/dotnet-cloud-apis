using System;
using System.Configuration;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.WindowsAzure.Storage.Queue;

using RationalZone.v4;

/// RationalZone.v4.CloudApis is a general purpose wrapper library for several OAuth
/// based cloud API service. Purpose is not be 100% wrapper on any but rather provide 
/// consistent horizontal abstraction that allows you to utilize multiple services 
/// transparently. The library basically handles the differences in OAuth implementation 
/// like the parameter names and security practices.
///
namespace RationalZone.v4.CloudApis
{
    /// CloudAccount contains the login information for one persons cloud API account
    ///
    public class CloudAccount
    {
        private static char ELEMENT_DELIMERATOR = ':';
        private static string URN_PREFIX = "clouadaccount:";

        protected static Dictionary<string, DateTime> RateLimits = new Dictionary<string, DateTime>();

		/// The API account instance for this account
		///
        public CloudApi Api { get; set; }

        public string Domain { get; set; }
        public string Token { get; set; }
		public string Id { get; set; }
		public string Email { get; set; }
		public string Name { get; set; }

        /// CloudAccount constructor from a token element array 
        ///
        /// @param string[] elements The token element array
		public CloudAccount(string[] elements) : this(Utils.stringUrlDecode(elements[0]), Utils.stringUrlDecode(elements[1]), Utils.stringUrlDecode(elements[2]), elements.Length >= 4 ? Utils.stringUrlDecode(elements[3]) : "" , elements.Length >= 5 ? Utils.stringUrlDecode(elements[4]) : "") { }

        /// CloudAccount constructor from a token string
        ///
        /// @param string token_string The token string.
		public CloudAccount(string account_string) : this(account_string.Replace(URN_PREFIX, "").Split(ELEMENT_DELIMERATOR)) { }

        /// CloudAccount constructor from the account elements
        ///
        /// @param string domain Domain of account
        /// @param string access_token OAuth access token
        /// @param string id API internal user id
        /// @param string email User email address
        /// @param string name User name 
        ///
		public CloudAccount(string domain, string id, string access_token, string email = "", string name = "")
		{
            if (Utils.stringIsEmpty(domain) || Utils.stringIsEmpty(access_token) || Utils.stringIsEmpty(id))
				throw new Exception("Invalid elements for a CloudApiAccount!");
            Domain = domain;
            Token = access_token;
			Id = id;
            Email = email;
            Name = name;
            Api = CloudApi.getByDomain(Domain);
            if (Api == null)
                throw new Exception("Invalid CloudApi domain '" + Domain + "'!");
            Api.Account = this;
		}

        /// Serialize a cloud account as a string 
        ///
        /// @returns String account token
        ///
		public override string ToString()
		{
			return URN_PREFIX + Utils.stringUrlEncode(Domain) + ELEMENT_DELIMERATOR + Utils.stringUrlEncode(Id) + ELEMENT_DELIMERATOR + Utils.stringUrlEncode(Token) + ELEMENT_DELIMERATOR + Utils.stringUrlEncode(Email) + ELEMENT_DELIMERATOR + Utils.stringUrlEncode(Name);
		}

        /// Accounts are considered equal if same user and token (user info might have changed)
        ///
        /// @param CloudAccount account 
        /// @returns Whether equal
        ///
		public bool Equals(CloudAccount account)
		{
			return (account != null && account.Id == Id && account.Token == Token);
		}

        /// Get how long in seconds until ratelimiting ends for this account
        ///
        /// @returns Ratelimit remaining in seconds
        ///
        public double getRatelimitTimeout()
        {
            if (Token != null && RateLimits.ContainsKey(Token))
                return RateLimits[Token].Subtract(DateTime.UtcNow).TotalSeconds;
            else
                return 0;
        }

        /// Set the end of ratelimit for this account
        ///
        /// @param DateTime ratelimit_timeout End of ratelimit in UTC-time
        /// @returns Whether ratelimit increased
        ///
        public bool setRatelimitTimeout(DateTime ratelimit_timeout)
        {
            if (Token != null && (!RateLimits.ContainsKey(Token) || (RateLimits[Token] < ratelimit_timeout)))
            {
                RateLimits[Token] = ratelimit_timeout;
                return true;
            }
            return false;
        }

        /// Set how long in seconds until ratelimiting ends for this account
        ///
        /// @param double ratelimit_timeout How long until ratelimit end in seconds
        /// @returns 
        ///
        public bool setRatelimitTimeout(double ratelimit_timeout)
        {
            return setRatelimitTimeout(DateTime.UtcNow.AddSeconds(ratelimit_timeout + 1));
        }
    }
    public abstract class CloudApi
	{
        protected static string Domain { get; set; }
        protected static string AppId { get; set; }
        protected static string AppSecret { get; set; }
        protected static string ApiUrl { get; set; }

        /// Current account for the API instance
        ///
        public CloudAccount Account	{ get; set; }

        /// Get an API instance for given domain
        ///
        /// @param string domain Domain of the cloud API
        /// @returns 
        ///
        public static CloudApi getByDomain(string domain)
        {
            if (domain != null) {
                domain = domain.ToLower().Replace(".com", "");
                switch (domain)
                {
                    case "dropbox":     return new DropboxApi();
                    case "slack":       return new SlackApi();
                    case "facebook":    return new FacebookApi();
                    case "twitter":     return new TwitterApi();
                }
            }
			return null;
		}

        public abstract string _createAuthorizationUrl(string redirect_url, string state);

        /// Create an authorization URL you can include in a login button
        ///
        /// @param string domain Domain of the API, e.g. "dropbox.com"
        /// @param string redirect_url Url where user is redirected after authorization, must match URL defined in API developer console
        /// @param string state Random state to match session and user in finalization 
        /// @returns Authorization URL
        ///
        public static string createAuthorizationUrl(string domain, string redirect_url, string state)
        {
            CloudApi api = getByDomain(domain);
            if (api != null)
                return api._createAuthorizationUrl(redirect_url, state);
			return null;
		}

        public abstract bool _finalizeAuthorization(string redirect_url);

        /// Finalize authorization by passing the redirection url to get a CloudApi (and CloudAccount)
        ///
        /// @param string url URL and parameters user was redirected to
        /// @returns CloudApi instance
        ///
        public static CloudApi finalizeAuthorization(string url)
        {
            CloudApi api = getByDomain(Utils.stringFindUrlValue(url, "domain"));
            if (api != null && api._finalizeAuthorization(url))
                return api;
            else
                return null;
        }

        /// Calculate OAuth signature from the request data
        ///
        /// @param string url URL of the request
        /// @param string method HTTP method of the request
        /// @param string parameter_string Request parameters sorted alphabetically and URL-formatted
        /// @param string consumer_secret Consumer secret to sign with
        /// @param string user_secret User secret to sign with
        /// @returns OAuth signature
        ///
        public static string _calculateOAuthSignature(string url, string method, string parameter_string, string consumer_secret, string user_secret)
        {
			//The oauth spec base string is a combination of the method, url and parameters
            string base_string = method + "&" + Utils.stringPercentEncode(url) + "&" + Utils.stringPercentEncode(parameter_string);
            string key = Utils.stringPercentEncode(consumer_secret) + "&";
			// in some phases of the Oauth flow we don't yet have the user secret (temporary or permanent)
            if (user_secret != null)
                key += Utils.stringPercentEncode(user_secret);
            return Utils.printBase64(Utils.printHmacSha1(base_string, Encoding.ASCII.GetBytes(key)));
        }
		
        /// Calculate OAuth authorization header calculation by hashing all parameters and content and signing the result.
        ///
        /// @param string url URL of the request
        /// @param string method HTTP method of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param string callback_url Callback URL if this is an OAuth authorization request 
        /// @param string nonce Random nonce for the signature
        /// @param string consumer_key Consumer key for your app
        /// @param string consumer_secret Consumer secret for your app
        /// @param string user_token User key
        /// @param string user_secret User secret
        /// @returns OAuth authorization header
        ///
        public static string _calculateOAuth1Authorization(string url, string method, Dictionary<string, string> parameters, string callback_url, string nonce, string consumer_key, string consumer_secret, string user_token, string user_secret)
        {
			// Build a sorted dictionary so we get all the parameters in alphabetical order
            IDictionary<string, string> auth_data;
            if (parameters != null)
                auth_data = new SortedDictionary<string, string>(parameters);
            else
                auth_data = new SortedDictionary<string, string>();

            if (callback_url != null)
                auth_data["oauth_callback"] = Utils.stringPercentEncode(callback_url);
            auth_data["oauth_consumer_key"] = consumer_key;
            auth_data["oauth_nonce"] = nonce;
            auth_data["oauth_signature_method"] = "HMAC-SHA1";
            auth_data["oauth_timestamp"] = Utils.stringUnixTimestamp();
            auth_data["oauth_token"] = user_token;
            auth_data["oauth_version"] = "1.0";
			// the parameter string is like url-parameters with quotes
            string parameter_string = Utils.printAttributes<string, string>(auth_data, "=", "&", "", "", true).Replace("\"", "");
            auth_data["oauth_signature"] = Utils.stringPercentEncode(_calculateOAuthSignature(url, method, parameter_string, consumer_secret, user_secret));
			// the actual header then is comma separated with quotes
            return "OAuth " + Utils.printAttributes<string, string>(auth_data, "=", ", ", "", "\"", true);
        }
		
        /// Default binding of the API and HTTP layers. May be overridden in an API implementation for custom handling.
        ///
        /// @param string url URL of the request
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param Dictionary<string, string> headers HTTP request headers
        /// @param Dictionary<string, string> response_headers Dictionary to receive HTTP response headers
        /// @param string result String to receive the result content
        /// @returns HTTP status code
        ///
        public virtual int _executeHttpRequest(string url, string method, string body, Dictionary<string, string> parameters, Dictionary<string, string> headers, Dictionary<string, string> response_headers, out string result)
        {
            return Utils.httpRequest(url, method, body, parameters, headers, response_headers, out result);
        }

        /// Default binding of the API and HTTP layers (e.g. how the URL is formed, what headers are needed). May be overridden in an API implementation for custom handling.
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param Dictionary<string, string> headers HTTP request headers
        /// @param Dictionary<string, string> response_headers Dictionary to receive HTTP response headers
        /// @param string api_result String to receive the API response content
        /// @returns HTTP status code
        ///
        public virtual int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
            string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, body, parameters, null, null, out http_result);
            api_result = http_result;
            return status;
        }

        /// Default binding of service and API layers (e.g. default parameters, interpreting status codes). May be overridden in an API implementation for custom handling.
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @returns API response
        ///
        public virtual string executeRequest(string service, string method = "GET", string body = null, Dictionary<string, string> parameters = null)
        {
            if (Account != null && service != null)
            {
                string result = "";
                int status = _executeApiRequest(service, method, body, parameters, out result);
                if (status >= 200 && status < 300)
                    return result;
            }
            return null;
        }
        /// Abstract placeholder to get user information 
        ///  
        /// @param string user_id Optional user id for other than the account user
        /// @returns User account data in JSON format
        ///
        public abstract string getUserInfo(string user_id = null);

    }

    public class DropboxApi : CloudApi
    {

        static Dictionary<string, string> _defaultHeaders = new Dictionary<string, string> { { "Accept", "application/json" }, { "Content-Type", "application/json" } };

        /// Default constructor
        ///
        public DropboxApi()
        {
            Domain = "dropbox.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.dropbox"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.dropbox"];
            ApiUrl = "https://api.dropboxapi.com/";
        }

        /// Constructor from an account 
        ///  
        /// @param CloudAccount account Account object 
        ///
        public DropboxApi(CloudAccount account) : this()
        {
            Account = account;
        }

        /// Overrides binding of the API and HTTP layers to add necessary headers and Bearer authorization
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param string api_result String to receive the API response content
        /// @returns HTTP status code
        ///
        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Accept", "application/json, text/javascript" }, { "Content-Type", "application/json" }, { "Authorization", "Bearer " + Account.Token } };
			string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, body, parameters, headers, null, out http_result);
            api_result = http_result;
			return status;
		}

		public override string _createAuthorizationUrl(string redirect_url, string state)
		{
			return "https://www.dropbox.com/oauth2/authorize?disable_signup=true&response_type=code&redirect_uri=" + Utils.urlSanitizeParameter(redirect_url, true, "domain=dropbox") + "&client_id=" + AppId + "&state=" + state;

		}

		public override bool _finalizeAuthorization(string url)
        {
            string code = Utils.stringFindUrlValue(url, "code");
			if (code != null)
            {
				// change the code we received for an access token
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=dropbox");
                Dictionary<string, string> headers = new Dictionary<string, string>(_defaultHeaders);
                headers["Authorization"] = Utils.httpCalculateBasicAuthentication(AppId, AppSecret);
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "grant_type", "authorization_code" }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "oauth2/token", "POST", null, parameters, headers, null, out http_result);
				string token = Utils.stringFindJsonValue(http_result, "access_token");
                string account_id = Utils.stringFindJsonValue(http_result, "account_id");
                if (token != null && account_id != null)
                {
					// replace auth header with real token
					headers["Authorization"] = "Bearer " + token;
					// get account info for id, name and email
                    status = _executeHttpRequest(ApiUrl + "2/users/get_account", "POST", "{\"account_id\":\"" + account_id + "\"}", null, headers, null, out http_result);
                    if (http_result != null)
                        Account = new CloudAccount(Domain, account_id, token, Utils.stringFindJsonValue(http_result, "email"), Utils.stringFindJsonValue(http_result, "display_name"));
                }
            }
            return Account != null;
        }

        /// Get user information 
        ///
        /// @param string user_id Optional user id for other than the account user
        /// @returns User account data in JSON format
        ///
		public override string getUserInfo(string user_id = null)
        {
            if (Account != null)
            {
                if (user_id == null)
                    user_id = Account.Id;
                return executeRequest("2/users/get_account", "POST", "{\"account_id\":\"" + user_id + "\"}");
            }
            return null;
        }
    }

    public class FacebookApi : CloudApi
    {
        /// Default constructor
        ///
        public FacebookApi()
        {
            Domain = "facebook.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.facebook"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.facebook"];
            CloudApi.ApiUrl = "https://graph.facebook.com/";
        }

        /// Constructor from an account 
        ///  
        /// @param CloudAccount account Account object 
        ///
        public FacebookApi(CloudAccount account) : this()
        {
            Account = account;
        }

        public override string _createAuthorizationUrl(string redirect_url, string state)
        {
            return "https://www.facebook.com/v2.8/dialog/oauth?response_type=code&scope=public_profile,user_friends,email&client_id=" + AppId + "&redirect_uri=" + Utils.urlSanitizeParameter(redirect_url, true, "domain=facebook") + "&state=" + state;
        }
        public override bool _finalizeAuthorization(string url)
        {
            string code = Utils.stringFindUrlValue(url, "code");
            if (code != null)
            {
				// trade code for access token
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=facebook");
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "client_id", AppId }, { "client_secret", AppSecret }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "v2.8/oauth/access_token", "POST", null, parameters, null, null, out http_result);
                string token = Utils.stringFindJsonValue(http_result, "access_token");
                if (token != null)
                {
					// get user account information
                    parameters = new Dictionary<string, string> { { "access_token", token }, { "fields", "id,email,first_name,last_name" } };
                    status = _executeHttpRequest(ApiUrl + "me", "POST", null, parameters, null, null, out http_result);
                    if (http_result != null)
                        Account = new CloudAccount(Domain, Utils.stringFindJsonValue(http_result, "id"), token, Utils.stringUtfDecode(Utils.stringFindJsonValue(http_result, "email")), Utils.stringFindJsonValue(http_result, "first_name") + " " + Utils.stringFindJsonValue(http_result, "last_name"));
                }
            }
            return Account != null;
        }

        /// Overrides binding of the API and HTTP layers to add access token parameter
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param string api_result String to receive the API response content
        /// @returns HTTP status code
        ///
        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
			if (parameters == null)
				parameters = new Dictionary<string, string>();
			parameters["access_token"] = Account.Token;
			string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, body, parameters, null, null, out http_result);
            api_result = http_result;
			return status;
		}

        /// Get user information 
        ///
        /// @param string user_id Optional user id for other than the account user
        /// @returns User account data in JSON format
        ///
		public override string getUserInfo(string user_id = null)
        {
            if (Account != null)
            {
                if (user_id == null)
                    user_id = Account.Id;
                return executeRequest("me");
            }
            return null;
        }

    }

	public class SlackApi : CloudApi
	{
        private static Dictionary<string, string> HEADERS = new Dictionary<string, string> { { "Accept", "application/json, text/javascript" } };

        /// Default constructor
        ///
        public SlackApi()
        {
            Domain = "slack.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.slack"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.slack"];
            ApiUrl = "https://slack.com/api/";
        }

        /// Constructor from an account 
        ///  
        /// @param CloudAccount account Account object 
        ///
        public SlackApi(CloudAccount account) : this() 
        {
            Account = account;
        }
		
		public override string _createAuthorizationUrl(string redirect_url, string state)
		{
			return "https://slack.com/oauth/authorize?scope=channels:read groups:read files:read files:write:user search:read users:read&client_id=" + AppId + "&redirect_uri=" + Utils.urlSanitizeParameter(redirect_url, true, "domain=slack") + "&state=" + state;

		}
        public override bool _finalizeAuthorization(string url)
        {
            string code = Utils.stringFindUrlValue(url, "code");
            if (code != null)
            {
				// first trade OAuth code for an access token
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=slack");
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "client_id", AppId }, { "client_secret", AppSecret }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "oauth.access", "POST", null, parameters, null, null, out http_result);
				string token = Utils.stringFindJsonValue(http_result, "access_token");
				if (token != null) {
					// then use the test service to fetch the user id
                    parameters = new Dictionary<string, string> { { "token", token } };
                    status = _executeHttpRequest(ApiUrl + "auth.test", "POST", null, parameters, null, null, out http_result);
                    string uid = Utils.stringFindJsonValue(http_result, "user_id");
                    if (uid != null)
                    {
						// finally get the users name and email
                        parameters.Add("user", uid); // need token + uid
                        status = _executeHttpRequest(ApiUrl + "users.info", "POST", null, parameters, null, null, out http_result);
                        if (http_result != null)
                        {
                            string name = Utils.stringFindJsonValue(http_result, "real_name");
                            if (name == null)
                            { // user might not have given the real name, resort to screen nick
                                name = Utils.stringFindJsonValue(http_result, "name");
                            }
                            Account = new CloudAccount(Domain, uid, token, Utils.stringFindJsonValue(http_result, "email"), name);
                        }
                    }
                }
            }
            return Account != null;
        }

        /// Overrides binding of the API and HTTP layers to add access token parameter
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param string api_result String to receive the API response content
        /// @returns HTTP status code
        ///
        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
			if (parameters == null)
				parameters = new Dictionary<string, string>();
			parameters["token"] = Account.Token;
			string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, body, parameters, null, null, out http_result);
            api_result = http_result;
			return status;
		}

        /// Get user information 
        ///
        /// @param string user_id Optional user id for other than the account user
        /// @returns User account data in JSON format
        ///
		public override string getUserInfo(string user_id = null)
        {
            if (Account != null)
            {
                if (user_id == null)
                    user_id = Account.Id;
                return executeRequest("users.info", "POST", null, new Dictionary<string, string> { { "user", user_id } });
            }
            return null;
        }

        /// Upload string content as a file in Slack 
        ///
        /// @returns User account data in JSON format
        ///
		public bool putFile(string path, string content)
        {
            if (path != null && Account != null)
            {
				int name_index = path.LastIndexOf('/');
				string name = path.Substring(name_index + 1);
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "filename", name } };
                return executeRequest("files.upload" + path, "POST","content="+content, parameters) != null;
            }
            return false;
        }
    }

    public class TwitterApi : CloudApi
    {
        protected static string OAuthUrl = "https://api.twitter.com/oauth/";
        protected static Dictionary<string, string> AuthorizationRequestTokens = new Dictionary<string, string>();
        protected static DateTime EPOCH_TIME = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);


        /// Default constructor
        ///
        public TwitterApi()
        {
            Domain = "twitter.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.twitter"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.twitter"];
            ApiUrl = "https://api.twitter.com/1.1/";            
        }
		
        /// Constructor from an account 
        ///  
        /// @param CloudAccount account Account object 
        ///
        public TwitterApi(CloudAccount account) : this () 
        {
            Account = account;
        }

        public override string _createAuthorizationUrl(string redirect_url, string state)
        {
			// Twitter decided to do it unlike anyone else and wants you to create single use token for the auth link. Note that no user token/secret at this point
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(OAuthUrl + "request_token", "POST", null, redirect_url + "?domain=twitter&state=" + state, state, AppId, AppSecret, null, null) } };
            string result = "";
            int status = _executeHttpRequest(OAuthUrl + "request_token", "POST", null, null, headers, null, out result);
            if (Utils.stringFindUrlValue(result, "oauth_callback_confirmed") == "true") {
                string token = Utils.stringFindUrlValue(result, "oauth_token");
                string secret = Utils.stringFindUrlValue(result, "oauth_token_secret");
				// need to store the token secret in the session since the auth callback does not have all info
                AuthorizationRequestTokens[token] = secret;
                return OAuthUrl + "authenticate?oauth_token=" + token;
            } else {
                return null;
            }
        }
		
        public override bool _finalizeAuthorization(string url)
        {
            string oauth_verifier = Utils.stringFindUrlValue(url, "oauth_verifier");
            string oauth_token = Utils.stringFindUrlValue(url, "oauth_token");
            if (oauth_verifier != null && oauth_token != null)
            {
				// this time the one time token we stored/received are used in Oauth header calculation as user token/secret
                string oauth_secret = AuthorizationRequestTokens[oauth_token];
                AuthorizationRequestTokens[oauth_token] = null;
                Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(OAuthUrl + "access_token", "POST", null, null, Utils.stringRandomize(16), AppId, AppSecret, oauth_token, oauth_secret) } };
                string result = "";
                int status = _executeHttpRequest(OAuthUrl + "access_token", "POST", null, new Dictionary<string, string> { { "oauth_verifier", oauth_verifier } }, headers, null, out result);
				// now we got the permanent user token/secret that we can use to calculate 
                string user_token = Utils.stringFindUrlValue(result, "oauth_token");
                string user_secret = Utils.stringFindUrlValue(result, "oauth_token_secret");
                string user_id = Utils.stringFindUrlValue(result, "user_id");
                if (user_token != null && user_secret != null && user_id != null)
                {
                    Dictionary<string, string> parameters = new Dictionary<string, string> { { "user_id", user_id } };
                    headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(ApiUrl + "users/show.json", "GET", parameters, null, Utils.stringRandomize(16), AppId, AppSecret, user_token, user_secret) } };
                    _executeHttpRequest(ApiUrl + "users/show.json", "GET", null, parameters, headers, null, out result);
                    if (result != null)
                        Account = new CloudAccount(Domain, Utils.stringFindJsonValue(result, "id_str"), user_id + "_" + user_token + "_" + user_secret, null, Utils.stringFindJsonValue(result, "name"));
                }
            }
            return Account != null;
        }

        /// Overrides binding of the API and HTTP layers to add authorization header and rate limit management 
        ///
        /// @param string service Name of the service
        /// @param string method HTTP method of the request
        /// @param string body HTTP body of the request
        /// @param Dictionary<string, string> parameters HTTP request parameters
        /// @param string api_result String to receive the API response content
        /// @returns HTTP status code
        ///
        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
			// check if we've already hit ratelimit this sessions [TODO: ratelimits do have service dependencies and might be possible to push the envelope by detailing this by service]
            if (Account.getRatelimitTimeout() > 0)
            {
                api_result = null;
                return 429;
            }
			// Twitter "access token" is actually combination of the user id, user token and user secret that are all needed separately in auth header calculation
            string[] token_parts = Account.Token.Split('_');
            string url = ApiUrl + service;
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(url, method, parameters, null, Utils.stringRandomize(16), AppId, AppSecret, token_parts[1], token_parts[2]) } };
            Dictionary<string, string> response_headers = new Dictionary<string, string>();
            string http_result = "";
            int status = _executeHttpRequest(url, method, null, parameters, headers, response_headers, out http_result);
			// let's see if we've hit the rate limit 
            if (status == 429 || (response_headers.ContainsKey("x-rate-limit-remaining") && response_headers["x-rate-limit-remaining"] == "0")) {
                int reset_seconds = 0;
				// if we get a reset time use it, otherwise use 15min default
                if (int.TryParse(response_headers["x-rate-limit-reset"], out reset_seconds))
                    Account.setRatelimitTimeout(EPOCH_TIME.AddSeconds(reset_seconds));
                else
                    Account.setRatelimitTimeout(DateTime.UtcNow.AddSeconds(15*60)); // 15 min is the default interval
            }
            api_result = http_result;
            return status;
        }

        /// Get user information 
        ///
        /// @param string user_id Optional user id for other than the account user
        /// @returns User account data in JSON format
        ///
        public override string getUserInfo(string user_id = null)
        {
            if (user_id == null)
                user_id = Account.Id;
            return executeRequest("users/show.json", "GET", null, new Dictionary<string, string> { { "user_id", user_id } });
        }

        /// Get follower data
        ///  
        /// @param string user_id Optional user id for other than the account user
        /// @returns 
        ///
        public string getFollowers(string user_id = null)
        {
            if (user_id == null)
                user_id = Account.Id;
            return executeRequest("followers/ids.json", "GET", null, new Dictionary<string, string> { { "user_id", user_id }, { "stringify_ids", "true" } });
        }

        /// Get tweet data 
        ///  
        /// @param string user_id Optional user id for other than the account user
        /// @param int count Number of tweets to return, -1 for maximum
        /// @param bool exclude_user_details Exclude user detail information
        /// @param bool exclude_replies Exclude tweets that are replies 
        /// @param bool exclude_retweets Exclude tweets that are retweets 
        /// @returns 
        ///
        public string getTweets(string user_id = null, int count=-1, bool exclude_user_details=false, bool exclude_replies=false, bool exclude_retweets = false )
        {
            if (user_id == null)
                user_id = Account.Id;
            if (count <= 0 || count > 3200)
                count = 3200;
            return executeRequest("statuses/user_timeline.json", "GET", null, new Dictionary<string, string> { { "user_id", user_id }, { "exclude_replies", exclude_replies.ToString() }, { "trim_user", exclude_user_details.ToString() }, { "include_rts", (!exclude_retweets).ToString() }, { "count", count.ToString() } });
        }
    }
}

