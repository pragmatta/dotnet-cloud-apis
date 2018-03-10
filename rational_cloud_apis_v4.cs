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

namespace RationalZone.v4.CloudApis
{
    public class CloudAccount
    {
		private static char ELEMENT_DELIMERATOR = ':';

        protected static Dictionary<string, DateTime> RateLimits = new Dictionary<string, DateTime>();

        public CloudApi Api { get; set; }

        public string Domain { get; set; }
        public string Token { get; set; }
		public string Id { get; set; }
		public string Email { get; set; }
		public string Name { get; set; }
		public CloudAccount(string[] elements)
		{
            Id = "";
            Email = "";
            Name = "";
            if (elements == null || elements.Length < 2 || Utils.stringIsEmpty(elements[0]) || Utils.stringIsEmpty(elements[1]))
				throw new Exception("Invalid elements for a CloudApiAccount!");
            Domain = elements[0];
            Token = elements[1];
            Api = CloudApi.getByDomain(Domain);
            if (Api == null)
                throw new Exception("Invalid CloudApi domain '" + Domain + "'!");
            Api.Account = this;
			if (elements.Length >= 3 && !Utils.stringIsEmpty(elements[2])) Id = elements[2];
			if (elements.Length >= 4 && !Utils.stringIsEmpty(elements[3])) Email = elements[3];
			if (elements.Length >= 5 && !Utils.stringIsEmpty(elements[4])) Name = elements[4];
		}
		public CloudAccount(string token_string) : this(Utils.stringUrlDecode(token_string).Split(ELEMENT_DELIMERATOR)) { }
		public CloudAccount(string domain, string token, string id = "", string email = "", string name = "") : this(new string[5] { domain, token, id, email, name }) { }

		public override string ToString()
		{
			return Utils.stringUrlEncode(Domain + ELEMENT_DELIMERATOR + Token + ELEMENT_DELIMERATOR + Id + ELEMENT_DELIMERATOR + Email + ELEMENT_DELIMERATOR + Name);
		}

		public bool Equals(CloudAccount account)
		{
			return (account != null && account.Id == Id && account.Email == Email && account.Token == Token);
		}
        public double getRatelimitTimeout()
        {
            if (Token != null && RateLimits.ContainsKey(Token))
                return RateLimits[Token].Subtract(DateTime.UtcNow).TotalSeconds;
            else
                return 0;
        }
        public bool setRatelimitTimeout(DateTime ratelimit_timeout)
        {
            if (Token != null && (!RateLimits.ContainsKey(Token) || (RateLimits[Token] < ratelimit_timeout)))
            {
                RateLimits[Token] = ratelimit_timeout;
                return true;
            }
            return false;
        }
        public bool setRatelimitTimeout(double ratelimit_timeout)
        {
            return setRatelimitTimeout(DateTime.UtcNow.AddSeconds(ratelimit_timeout + 1));
        }
    }
    public abstract class CloudApi
	{
        public enum Domains { dropbox, slack, twitter, facebook };

        protected static string Domain { get; set; }
        protected static string AppId { get; set; }
        protected static string AppSecret { get; set; }
        protected static string ApiUrl { get; set; }

        public CloudAccount Account	{ get; set; }

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

        public static string createAuthorizationUrl(string domain, string redirect_url, string state)
        {
            CloudApi api = getByDomain(domain);
            if (api != null)
                return api._createAuthorizationUrl(redirect_url, state);
			return null;
		}

        public abstract bool _finalizeAuthorization(string redirect_url);

        public static CloudApi finalizeAuthorization(string url)
        {
            CloudApi api = getByDomain(Utils.stringFindUrlValue(url, "domain"));
            if (api != null && api._finalizeAuthorization(url))
                return api;
            else
                return null;
        }
        public static string _calculateOAuthSignature(string url, string method, string parameter_string, string consumer_secret, string user_secret)
        {
            string base_string = method + "&" + Utils.stringPercentEncode(url) + "&" + Utils.stringPercentEncode(parameter_string);
            string key = Utils.stringPercentEncode(consumer_secret) + "&";
            if (user_secret != null)
                key += Utils.stringPercentEncode(user_secret);
            return Utils.printBase64(Utils.printHmacSha1(base_string, Encoding.ASCII.GetBytes(key)));
        }
        public static string _calculateOAuth1Authorization(string url, string method, Dictionary<string, string> parameters, string callback_url, string nonce, string consumer_key, string consumer_secret, string user_token, string user_secret)
        {
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
            string parameter_string = Utils.printAttributes<string, string>(auth_data, "=", "&", "", "", true).Replace("\"", "");
            auth_data["oauth_signature"] = Utils.stringPercentEncode(_calculateOAuthSignature(url, method, parameter_string, consumer_secret, user_secret));
            return "OAuth " + Utils.printAttributes<string, string>(auth_data, "=", ", ", "", "\"", true);
        }
        public static int _executeHttpRequest(string url, string method, string body, Dictionary<string, string> parameters, Dictionary<string, string> headers, Dictionary<string, string> response_headers, out string result)
        {
            return Utils.httpRequest(url, method, body, parameters, headers, response_headers, out result);
        }

        public virtual int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
            string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, null, parameters, null, null, out http_result);
            api_result = http_result;
            return status;
        }

        public string executeRequest(string service, string method, string body, Dictionary<string, string> parameters = null)
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
    }

    public class DropboxApi : CloudApi
    {
        public DropboxApi()
        {
            Domain = "dropbox.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.dropbox"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.dropbox"];
            ApiUrl = "https://api.dropbox.com/";
        }
        public DropboxApi(CloudAccount account) 
		{ 
			Account = account;
		}
        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Accept", "application/json, text/javascript" }, { "Authorization", "Bearer " + Account.Token } };
			string http_result = "";
            int status = _executeHttpRequest(ApiUrl + service, method, body, parameters, headers, null, out http_result);
            api_result = http_result;
			return status;
		}
		public override string _createAuthorizationUrl(string redirect_url, string state)
		{
			return "https://www.dropbox.com/1/oauth2/authorize?disable_signup=true&response_type=code&redirect_uri=" + Utils.urlSanitizeParameter(redirect_url, true, "domain=dropbox") + "&client_id=" + AppId + "&state=" + state;

		}
		public override bool _finalizeAuthorization(string url)
        {
            string code = Utils.stringFindUrlValue(url, "code");
			if (code != null)
            {
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=dropbox");
                Dictionary<string, string> headers = new Dictionary<string, string> { { "Accept", "application/json, text/javascript" }, { "Authorization", "Bearer " + Account.Token } };
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "grant_type", "authorization_code" }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "1/oauth2/token", "POST", null, parameters, headers, null, out http_result);
				string token = Utils.stringFindJsonValue(http_result, "access_token");
                if (token != null)
                {
                    status = _executeHttpRequest(ApiUrl + "1/account/info", "GET", null, null, headers, null, out http_result);
                    if (http_result != null)
                        Account = new CloudAccount(Domain, token, Utils.stringFindJsonNumber(http_result, "uid"), Utils.stringFindJsonValue(http_result, "email"), Utils.stringFindJsonValue(http_result, "display_name"));
                }
            }
            return Account != null;
        }

		public bool putFile(string path, string content)
        {
            if (path != null && Account != null)
            {
                //string url = "https://api-content.dropbox.com/1/files_put/sandbox" + path;
                return executeRequest("1/files_put/sandbox" + path, "PUT", content) != null;
            }
            return false;
        }
    }

	public class SlackApi : CloudApi
	{
        private static Dictionary<string, string> HEADERS = new Dictionary<string, string> { { "Accept", "application/json, text/javascript" } };

        public SlackApi()
        {
            Domain = "slack.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.slack"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.slack"];
            ApiUrl = "https://slack.com/api/";
        }
        public SlackApi(CloudAccount account)
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
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=slack");
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "client_id", AppId }, { "client_secret", AppSecret }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "oauth.access", "POST", null, parameters, null, null, out http_result);
				string token = Utils.stringFindJsonValue(http_result, "access_token");
				if (token != null) {
                    parameters = new Dictionary<string, string> { { "token", token } };
                    string uid_data = executeRequest("auth.test", "GET", null, parameters);
                    string uid = Utils.stringFindJsonValue(uid_data, "user_id");
                    if (uid != null)
                    {
                        parameters.Add("user", uid); // need token + uid
                        string user_data = executeRequest("users.info", "GET", null, parameters);
                        if (user_data != null)
                        {
                            string name = Utils.stringFindJsonValue(user_data, "real_name");
                            if (name == null)
                            { // user might not have given the real name, resort to screen nick
                                name = Utils.stringFindJsonValue(user_data, "name");
                            }
                            Account = new CloudAccount(Domain, token, uid, Utils.stringFindJsonValue(user_data, "email"), name);
                        }
                    }
                }
            }
            return Account != null;
        }

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

    public class FacebookApi : CloudApi
    {
        public FacebookApi()
        {
            Domain = "facebook.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.facebook"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.facebook"];
            CloudApi.ApiUrl = "https://graph.facebook.com/";
        }
        public FacebookApi(CloudAccount account)
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
                string redirect_url = Utils.urlSanitizeParameter(Utils.urlTrimQuery(url), true, "domain=facebook");
                Dictionary<string, string> parameters = new Dictionary<string, string> { { "client_id", AppId }, { "client_secret", AppSecret }, { "redirect_uri", redirect_url }, { "code", code } };
                string http_result = "";
                int status = _executeHttpRequest(ApiUrl + "v2.8/oauth/access_token", "POST", null, parameters, null, null, out http_result);
                string token = Utils.stringFindJsonValue(http_result, "access_token");
                if (token != null)
                {
                    parameters = new Dictionary<string, string> { { "access_token", token }, { "fields", "id,email,first_name,last_name" } };
                    status = _executeHttpRequest(ApiUrl + "me", "POST", null, parameters, null, null, out http_result);
                    if (http_result != null)
                        Account = new CloudAccount(Domain, token, Utils.stringFindJsonValue(http_result, "id"), Utils.stringUtfDecode(Utils.stringFindJsonValue(http_result, "email")), Utils.stringFindJsonValue(http_result, "first_name") + " " + Utils.stringFindJsonValue(http_result, "last_name"));
                }
            }
            return Account != null;
        }

    }

    public class TwitterApi : CloudApi
    {
        protected static string OAuthUrl = "https://api.twitter.com/oauth/";
        protected static Dictionary<string, string> AuthorizationRequestTokens = new Dictionary<string, string>();
        protected static DateTime EPOCH_TIME = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);


        public TwitterApi()
        {
            Domain = "twitter.com";
            AppId = ConfigurationManager.AppSettings["dotnet-cloud-apis.appid.twitter"];
            AppSecret = ConfigurationManager.AppSettings["dotnet-cloud-apis.appsecret.twitter"];
            ApiUrl = "https://api.twitter.com/1.1/";            
        }
        public TwitterApi(CloudAccount account)
        {
            Account = account;
        }

        public override int _executeApiRequest(string service, string method, string body, Dictionary<string, string> parameters, out string api_result)
        {
            if (Account.getRatelimitTimeout() > 0)
            {
                api_result = null;
                return 429;
            }
            string[] token_parts = Account.Token.Split('_');
            string url = ApiUrl + service;
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(url, method, parameters, null, Utils.stringRandomize(16), AppId, AppSecret, token_parts[1], token_parts[2]) } };
            Dictionary<string, string> response_headers = new Dictionary<string, string>();
            string http_result = "";
            int status = _executeHttpRequest(url, method, null, parameters, headers, response_headers, out http_result);
            if (status == 429 || (response_headers.ContainsKey("x-rate-limit-remaining") && response_headers["x-rate-limit-remaining"] == "0")) {
                int reset_seconds = 0;
                if (int.TryParse(response_headers["x-rate-limit-reset"], out reset_seconds))
                    Account.setRatelimitTimeout(EPOCH_TIME.AddSeconds(reset_seconds));
                else
                    Account.setRatelimitTimeout(DateTime.UtcNow.AddSeconds(15*60)); // 15 min is the default interval
            }
            api_result = http_result;
            return status;
        }

        public override string _createAuthorizationUrl(string redirect_url, string state)
        {
            Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(OAuthUrl + "request_token", "POST", null, "https://sanakoe.azurewebsites.net/v4/authorize_finalize.aspx?domain=twitter.com&state=" + state, state, AppId, AppSecret, null, null) } };
            string result = "";
            int status = _executeHttpRequest(OAuthUrl + "request_token", "POST", null, null, headers, null, out result);
            if (Utils.stringFindUrlValue(result, "oauth_callback_confirmed") == "true") {
                string token = Utils.stringFindUrlValue(result, "oauth_token");
                string secret = Utils.stringFindUrlValue(result, "oauth_token_secret");
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
                string oauth_secret = AuthorizationRequestTokens[oauth_token];
                AuthorizationRequestTokens[oauth_token] = null;
                Dictionary<string, string> headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(OAuthUrl + "access_token", "POST", null, null, Utils.stringRandomize(16), AppId, AppSecret, oauth_token, oauth_secret) } };
                string result = "";
                int status = _executeHttpRequest(OAuthUrl + "access_token", "POST", null, new Dictionary<string, string> { { "oauth_verifier", oauth_verifier } }, headers, null, out result);
                string user_token = Utils.stringFindUrlValue(result, "oauth_token");
                string user_secret = Utils.stringFindUrlValue(result, "oauth_token_secret");
                string user_id = Utils.stringFindUrlValue(result, "user_id");
                if (user_token != null && user_secret != null && user_id != null)
                {
                    Dictionary<string, string> parameters = new Dictionary<string, string> { { "user_id", user_id } };
                    headers = new Dictionary<string, string> { { "Authorization", _calculateOAuth1Authorization(ApiUrl + "users/show.json", "GET", parameters, null, Utils.stringRandomize(16), AppId, AppSecret, user_token, user_secret) } };
                    _executeHttpRequest(ApiUrl + "users/show.json", "GET", null, parameters, headers, null, out result);
                    if (result != null)
                        Account = new CloudAccount(Domain, user_id + "_" + user_token + "_" + user_secret, Utils.stringFindJsonValue(result, "id_str"), null, Utils.stringFindJsonValue(result, "name"));
                }
            }
            return Account != null;
        }

        public string getUserInfo(string user_id = null)
        {
            if (user_id == null)
                user_id = Account.Id;
            return executeRequest("users/show.json", "GET", null, new Dictionary<string, string> { { "user_id", user_id } });
        }
        public string getFollowers(string user_id = null)
        {
            if (user_id == null)
                user_id = Account.Id;
            return executeRequest("followers/ids.json", "GET", null, new Dictionary<string, string> { { "user_id", user_id }, { "stringify_ids", "true" } });
        }

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

