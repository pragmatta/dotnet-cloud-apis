# Rational Cloud API

## Introduction
Rational Cloud APIs is a general purpose wrapper library for several OAuth based cloud API service. Purpose is not be 100% wrapper on any but rather provide consistent horizontal abstraction that allows you to utilize multiple services transparently. The library basically handles the differences in OAuth implementation like the parameter names and security practices. For example it's easy to create login/signup or single purpose integrations like getting a file or sending a message.

Currently supported APIs
* Dropbox
* Facebook
* Slack
* Twitter

If you expand, considering submitting back!

## Getting Started

### Configure App Tokens
In your ConfigurationManager AppSettings add your AppId and AppSecret as "dotnet-azure-objects.appid.domain" and "dotnet-azure-objects.appsecret.domain" for all cloud APIs you want to support. I.e. you have to sign up as a developer, create a new app and get AppId and AppSecret values (these might have different names in different places).

```
<add key="dotnet-azure-objects.appid.dropbox" value="..." />
<add key="dotnet-azure-objects.appsecret.dropbox" value="..." />
```

### Create A Login Page
First thing you need to do is to derive a class from one of the base classes: 
```
<% 
	Session["authorize_start_state"] = Utils.stringRandomize(128); // generate a random state for auth process
	string dropbox_url = CloudApi.createAuthorizationUrl("dropbox.com", LINK_TO_FINALIZE_PAGE, Session["authorize_start_state"]);
%>
<a href="<%= dropbox_url %>" target="_parent">Login With Dropbox</a>
```

### Create A Login Finalize Page
Then create a page where LINK_TO_FINALIZE_PAGE points to get an account info
```
if (Request["state"] == Session["authorize_start_state"]) { // state from OAuth redirect must match session
	CloudApi api = CloudApi.finalizeAuthorization(Request.Url.AbsoluteUri); // create an api & account instance
	if (api != null) {
		CloudAccount account = api.Account; // do something with the account and save it
}
```

### Use The API
One you have created an API/account-instance, you can make calls using the executeRequest-method. For example to search Dropbox files using the API endpoint https://www.dropbox.com/developers/documentation/http/documentation#files-search
```
Dictionary<string, string> parameters = new Dictionary<string, string> { 
	{ "path", ""},
    { "query", "prime numbers"},
    { "start", 0},
    { "max_results", 100},
    { "mode", "filename" }
};
string result = executeRequest("2/files/search", "GET", null, parameters);
```


## Documentation
See [**http://github.com/RationalMatta/dotnet-cloud-apis/blob/master/documentation/html/annotated.html**](http://htmlpreview.github.io/?https://github.com/RationalMatta/dotnet-cloud-apis/blob/master/documentation/html/annotated.html) for more

## Changelog
### v4.1.1
- First public release
