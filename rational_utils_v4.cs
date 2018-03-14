using System;
using System.Configuration;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
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

using RationalZone;

namespace RationalZone.v4
{
    public class Utils
    {
        /// Returns whether a string is null or empty
        ///
        /// @param string string str The string
        public static bool stringIsEmpty(string str)
        {
            return str == null || str == string.Empty;
        }
        /// Returns a "percent encoded" string of a string
        ///
        /// @param string str The string
        public static string stringPercentEncode(string str)
        {
            if (str != null)
                return Uri.EscapeDataString(str);
            else
                return null;
        }
        /// Returns an url-encoded version of a string
        ///
        /// @param string str The string
        public static string stringUrlEncode(string str)
        {
            if (str != null)
                return HttpUtility.UrlEncode(str);
            else
                return null;
        }
        /// Returns an url-decoded version of a string
        ///
        /// @param string str The string
        public static string stringUrlDecode(string str)
        {
            if (str != null)
                return HttpUtility.UrlDecode(str);
            else
                return null;
        }
        /// Returns a string with utf-codes decoded
        ///
        /// @param string str The string
        public static string stringUtfDecode(string str)
        {
            if (str != null)
                return System.Uri.UnescapeDataString(str);
            else
                return null;
        }
        /// If string matches sanitization regex, returns the original string, null otherwise
        ///
        /// @param string str The string to sanitize
        /// @param string regex The regular expression to match
        public static string stringSanitize(string str, string regex)
        {
            if (str != null && Regex.IsMatch(str, regex, RegexOptions.IgnoreCase))
                return str;
            else
                return null;
        }
        /// Sanitizes an email string
        ///
        /// @param string email Email string
        public static string stringSanitizeEmail(string email)
        {
            return stringSanitize(email, @"^[a-zA-Z0-9\-_\+\.]+@[a-zA-Z0-9\-_\+\.]+\.[a-zA-Z0-9\-_\+\.]+$");
        }
        /// Sanitizes a token string
        ///
        /// @param string token Token string
        public static string stringSanitizeToken(string token)
        {
            return stringSanitize(token, @"^[a-zA-Z0-9\-_\=\+\/\.\%\:\@\s]{1,1024}$");
        }
        /// 
        ///
        /// @param string  
        public static string stringSanitizeName(string name)
        {
            return stringSanitize(name, @"^[a-zA-Z0-9\-_\=\+\/\s]{1,1024}$");
        }
        /// 
        ///
        /// @param string  
        public static string urlSanitize(string url)
        {
            if (url != null && Uri.IsWellFormedUriString(url, UriKind.RelativeOrAbsolute))
                return url;
            else
                return null;
        }
        /// Sanitizes an URL and optionally URL-encodes result
        ///
        /// @param string url Url string
        /// @param string encode Whether to URL-encode result
        public static string urlSanitizeParameter(string url, bool encode)
        {
            return urlSanitizeParameter(url, encode, null);
        }
        /// Sanitizes an URL, appends extra parameters and optionally URL-encodes result 
        ///
        /// @param string url Url string
        /// @param string encode Whether to URL-encode result
        /// @param string extra_params Parameter-string to append to URL
        public static string urlSanitizeParameter(string url, bool encode, string extra_params)
        {
            if (url != null && Uri.IsWellFormedUriString(url, UriKind.RelativeOrAbsolute))
            {
                if (extra_params != null)
                {
                    string delimerator = (url.IndexOf('?') >= 0) ? "&" : "?";
                    url = url + delimerator + extra_params;
                }
                if (encode)
                    url = HttpUtility.UrlEncode(url);
                return url;
            }
            else
            {
                return null;
            }
        }
        /// Sanitize an alpha-numeric string
        ///
        /// @param string str The string
        public static string stringSanitizeAlphaNumeric(string str)
        {
            return stringSanitize(str, @"^[a-zA-Z0-9]{1,1024}$");
        }
        /// Sanitize a float string
        ///
        /// @param string float_str The string
        public static string stringSanitizeFloat(string float_str)
        {
            return stringSanitize(float_str, @"^[0-9]{1,1024}\.?[0-9]{0,1024}$");
        }
        /// Sanitize a date string
        ///
        /// @param string date The string
        public static DateTime stringSanitizeDate(string date)
        {
            DateTime result = DateTime.Today;
            if (DateTime.TryParse(date, out result))
                return result;
            else
                return DateTime.MinValue;
        }
        /// Generate a UNIX timestamp of now
        ///
        public static string stringUnixTimestamp()
        {
            return (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds.ToString();
        }
        /// Generate a random string of given length
        ///
        /// @param string length The length
        public static string stringRandomize(int length)
        {
            string result = "";
            while (result.Length < length)
                result += Regex.Replace(System.Web.Security.Membership.GeneratePassword(128, 1), @"[^a-zA-Z0-9]", m => ""); // remove non-alphanumerics
            return result.Substring(0, length);
        }

        /// Find a JSON string value from a string
        ///
        /// @param string json_data The JSON string
        /// @param string key The name of the key
        public static string stringFindJsonValue(string json_data, string key)
        {
            if (json_data != null && key != null)
            {
                key = "\"" + key + "\"";
                int start = json_data.IndexOf(key);
                if (start >= 0)
                {
                    start = json_data.IndexOf("\"", start + key.Length + 1) + 1;
                    int end = json_data.IndexOf("\"", start);
                    if (start > 0 && end > start)
                        return json_data.Substring(start, end - start);
                }
            }
            return null;
        }

        /// Find a JSON number (or boolean) value from a string
        ///
        /// @param string json_data The JSON string
        /// @param string key The name of the key
        public static string stringFindJsonNumber(string json_data, string key)
        {
            if (json_data != null && key != null)
            {
                key = "\"" + key + "\"";
                int start = json_data.IndexOf(key);
                if (start >= 0)
                {
                    start = start + key.Length + 2;
                    int end = json_data.IndexOf(",", start);
                    if (end < 0)
                        end = json_data.IndexOf("}", start);
                    if (start > 0 && end > start)
                        return json_data.Substring(start, end - start).Trim();
                }
            }
            return null;
        }

        /// Find an URL parameter value
        ///
        /// @param string url_data The URL-string
        /// @param string key The parameter name
        public static string stringFindUrlValue(string url_data, string key)
        {
            if (url_data != null && key != null)
            {
                key = key + "=";
                int start = url_data.IndexOf(key);
                if (start >= 0)
                {
                    start = start + key.Length;
                    int end = url_data.IndexOf("&", start);
                    if (end > start)
                        return url_data.Substring(start, end - start);
                    else
                        return url_data.Substring(start); // end of url-string
                }
            }
            return null;
        }

        /// Trim the query-part from an URL
        ///
        /// @param string url The URL
        public static string urlTrimQuery(string url)
        {
            if (url != null)
            {
                int url_param_index = url.IndexOf("?");
                if (url_param_index > 0)
                    return url.Substring(0, url_param_index);
                else
                    return url;
            }
            return null;
        }
        /// Print a collection of KeyValuePairs using given delimeters and wrappers
        ///
        /// @param string attributes The attribute collection
        /// @param string value_delimeter The delimeter between key and value (e.g. "=")
        /// @param string attribute_delimeter The delimeter between KeyValuePairs (e.g. "\n")
        /// @param string key_wrapper The wrapper for keys (e.g. "'")
        /// @param string value_wrapper The wrapper for values (e.g. "'")
        /// @param string trim_empty_values Whether to trim empty values
        public static string printAttributes<TKey, TValue>(ICollection<KeyValuePair<TKey, TValue>> attributes, string value_delimeter, string attribute_delimeter, string key_wrapper = "", string value_wrapper = "", bool trim_empty_values = false)
        {
            if (attributes != null)
            {
                StringBuilder result = new StringBuilder();
                foreach (KeyValuePair<TKey, TValue> item in attributes)
                {
                    if (item.Value != null)
                    {
                        string value = item.Value.ToString();
                        if (value != "" || !trim_empty_values)
                        {
                            if (result.Length > 0)
                                result.Append(attribute_delimeter);
                            result.Append(key_wrapper).Append(item.Key).Append(key_wrapper).Append(value_delimeter).Append(value_wrapper).Append(value).Append(value_wrapper);
                        }
                    }
                }
                return result.ToString();
            }
            return null;
        }
        /// Print a collection of values using given delimeters and wrappers
        ///
        /// @param string attributes The attribute collection
        /// @param string attribute_delimeter The delimeter between values (e.g. "\n")
        /// @param string value_wrapper The wrapper for values (e.g. "'")
        /// @param string trim_empty_values Whether to trim empty values
        public static string printCollection<TValue>(ICollection<TValue> collection, string attribute_delimeter, string value_wrapper = "", bool trim_empty_values = false)
        {
            if (collection != null)
            {
                StringBuilder result = new StringBuilder();
                foreach (TValue item in collection)
                {
                    if (item != null)
                    {
                        string value = item.ToString();
                        if (value != "" || !trim_empty_values)
                        {
                            if (result.Length > 0)
                                result.Append(attribute_delimeter);
                            result.Append(value_wrapper).Append(value).Append(value_wrapper);
                        }
                    }
                }
                return result.ToString();
            }
            return null;
        }
        /// Print a byte array as a DBase64 string
        ///
        /// @param string bytes The byte array
        public static string printDBase64(byte[] bytes)
        {
            if (bytes != null)
                return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').Replace("=", string.Empty);
            else
                return null;
        }
        /// Print a string as a DBase64 string
        ///
        /// @param string str The string
        public static string printDBase64(string str)
        {
            if (str != null)
                return printDBase64(System.Text.Encoding.ASCII.GetBytes(str));
            else
                return null;
        }

        /// Print a byte array as a Base64 string
        ///
        /// @param string bytes The byte array
        public static string printBase64(byte[] bytes)
        {
            if (bytes != null)
                return Convert.ToBase64String(bytes);
            else
                return null;
        }
        /// Print a string as a Base64 string
        ///
        /// @param string str The string
        public static string printBase64(string str)
        {
            if (str != null)
                return printBase64(System.Text.Encoding.ASCII.GetBytes(str));
            else
                return null;
        }

        /// Print a byte array as a hex string
        ///
        /// @param string bytes The byte array
        public static string printHexString(byte[] bytes)
        {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                b.Append(bytes[i].ToString("x2"));
            }
            return b.ToString();
        }
        /// Print an MD5 hash of a string 
        ///
        /// @param string str The string
        public static byte[] printMd5(string str)
        {
            if (str != null)
            {
                MD5 md5 = MD5.Create();
                return md5.ComputeHash(System.Text.Encoding.ASCII.GetBytes(str));
            }
            return null;
        }
        /// Print an SHA256 hash of a string 
        ///
        /// @param string str The string
        public static byte[] printSha256(string str)
        {
            if (str != null)
            {
                SHA256 sha256 = SHA256.Create();
                return sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(str));
            }
            return null;
        }
        /// Print an SHA1 HMAC digest of a string 
        ///
        /// @param string str The string
        public static byte[] printHmacSha1(string str, byte[] key)
        {
            if (str != null)
            {
                HMACSHA1 myhmacsha1 = new HMACSHA1(key);
                byte[] byteArray = Encoding.ASCII.GetBytes(str);
                MemoryStream stream = new MemoryStream(byteArray);
                return myhmacsha1.ComputeHash(stream);
            }
            return null;
        }

        private const string _AesIV256 = "!YTJ8WUYITDSDFLK";
        /// Encrypt a string using AES256
        ///
        /// @param string str The string
        /// @param string key The key
        public static string aes256Encrypt(string str, string key)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.IV = Encoding.UTF8.GetBytes(_AesIV256);
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] src = Encoding.Unicode.GetBytes(str);
            using (ICryptoTransform encrypt = aes.CreateEncryptor())
            {
                byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                return Convert.ToBase64String(dest);
            }
        }

        /// Decrypt a string using AES256
        ///
        /// @param string str The string
        /// @param string key The key
        public static string aes256Decrypt(string str, string key)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.IV = Encoding.UTF8.GetBytes(_AesIV256);
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] src = System.Convert.FromBase64String(str);
            using (ICryptoTransform decrypt = aes.CreateDecryptor())
            {
                byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                return Encoding.Unicode.GetString(dest);
            }
        }

        /// Calculate a HTTP basic auth header
        ///
        /// @param string username The username
        /// @param string password The password
        public static string httpCalculateBasicAuthentication(string username, string password)
        {
            string authInfo = username + ":" + password;
            return "Basic " + Convert.ToBase64String(Encoding.Default.GetBytes(authInfo));
        }
        /// Print a http request parameter as key-value-pair using given delimeter
        ///
        /// @param string request The HttpRequest-object
        /// @param string param The name of the parameter
        /// @param string delimerator The delimerator
        public static string httpGetParameterAsString(HttpRequest request, string param, string delimerator)
        {
            string value = request[param];
            if (value != null)
                return delimerator + param + "=" + value;
            else
                return "";
        }

        /// Append a dictionary of parameters to an URL
        ///
        /// @param string url The URL
        /// @param string parameters The dictionary of string parameters
        public static string httpUrlAddParameters(string url, Dictionary<string, string> parameters)
        {
            return httpUrlAddParameters(url, printAttributes(parameters, "=", "&"));
        }

        /// Append a parameter-string to an URL
        ///
        /// @param string url The URL
        /// @param string parameters The parameter-string
        public static string httpUrlAddParameters(string url, string parameters)
        {
            if (!stringIsEmpty(parameters))
            {
                int query_delimerator = url.IndexOf('?');
                if (query_delimerator > 0)
                {
                    if (query_delimerator < url.Length - 1) // else there's already a trailing '?'
                        url = url + "&";
                }
                else
                {
                    url = url + "?";
                }
                url = url + parameters;
            }
            return url;
        }

        /// Execute a http request and get the result and status code as response
        ///
        /// @param string url The URL
        /// @param string result The out-parameter to store the result in
        public static int httpRequest(string url, out string result)
        {
            return httpRequest(url, null, null, null, null, null, out result);
        }
        protected static void _httpCollectResponseHeaders(HttpWebResponse response, Dictionary<string, string> headers)
        {
            if (headers != null && response != null)
                foreach (string key in response.Headers)
                    headers.Add(key, response.Headers[key]);
        }
        /// Execute a http request using given parameters and get the response headers, result and status code as response
        ///
        /// @param string url The URL
        /// @param string method The HTTP method name
        /// @param string body The HTTP body content
        /// @param string parameters The dictionary of request parameters
        /// @param string headers The dictionary of request headers
        /// @param string response_headers The dictionary of receive response headers
        /// @param string result The out-parameter to store the result in
        public static int httpRequest(string url, string method, string body, Dictionary<string, string> parameters, Dictionary<string, string> headers, Dictionary<string, string> response_headers, out string result)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(httpUrlAddParameters(url, parameters));
            HttpWebResponse response = null;
            try
            {
                if (headers != null)
                    foreach (KeyValuePair<string, string> kvp in headers)
                        switch (kvp.Key.ToLower())
                        {
                            case "accept":
                                req.Accept = kvp.Value;
                                break;
                            case "content-type":
                                req.ContentType = kvp.Value;
                                break;
                            default:
                                req.Headers.Add(kvp.Key, kvp.Value);
                                break;
                        }

                if (method != null)
                    req.Method = method;

                req.ContentLength = 0;
                if (req.Method == "POST" && req.ContentType == null)
                    req.ContentType = "application/x-www-form-urlencoded";

                if (body != null)
                {
                    byte[] request_data = Encoding.UTF8.GetBytes(body);
                    req.ContentLength = request_data.Length;
                    Stream output_data = req.GetRequestStream();
                    output_data.Write(request_data, 0, request_data.Length);
                    output_data.Close();
                }

                response = (HttpWebResponse)req.GetResponse();
            }
            catch (WebException e)
            {
                response = e.Response as HttpWebResponse;
            }
            try
            {
                StreamReader response_stream = new StreamReader(response.GetResponseStream());
                result = response_stream.ReadToEnd();
                _httpCollectResponseHeaders(response, response_headers);
                return (int)response.StatusCode;
            }
            catch (Exception e)
            {
                result = null;
            }
            return 0;
        }
        /// Execute a http request using given parameters asynchronously without waiting for the response
        ///
        /// @param string url The URL
        public static bool httpRequestAsync(string url)
        {
            return httpRequestAsync(url, null, null, null);
        }

        /// @param string url The URL
        /// @param string method The HTTP method name
        /// @param string body The HTTP body content
        /// @param string parameters The dictionary of request parameters
        /// @param string headers The dictionary of request headers
        ///
        /// @param string  
        public static bool httpRequestAsync(string url, string method, string body, string[] headers)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);

                if (headers != null)
                    for (int i = 0; i < headers.Length; i++)
                        req.Headers.Add(headers[i]);

                if (method != null)
                    req.Method = method;

                if (body != null)
                {
                    byte[] request_data = Encoding.UTF8.GetBytes(body);
                    req.ContentLength = request_data.Length;
                    Stream output_data = req.GetRequestStream();
                    output_data.Write(request_data, 0, request_data.Length);
                    output_data.Close();
                }

                IAsyncResult res = req.BeginGetResponse(new AsyncCallback(httpRequestFinish), req);
                return res != null;
            }
            catch (Exception e) { }
            return false;

        }
        public static void httpRequestFinish(IAsyncResult async_result)
        {
            HttpWebRequest request = (HttpWebRequest)async_result.AsyncState;
            HttpWebResponse response = (HttpWebResponse)request.EndGetResponse(async_result);
        }
        public static bool httpIsRequestProduction(HttpRequest request)
        {
            return (request != null) && !request.IsLocal && (request.Url.Host.ToLower().IndexOf("staging") < 0);
        }
        /// Get the file size in bytes, -1 for invalid
        ///
        /// @param string path The path to file
        public static long fileSize(string path)
        {
            try
            {
                FileInfo fi = new FileInfo(path);
                return fi.Length;
            }
            catch (Exception e)
            {
                return -1;
            }
        }

        /// Resize an image file as ratio of the current size
        ///
        /// @param string path The path to the input file
        /// @param string resized_path The path to the resize file
        /// @param string resize_ratio The resize ratio with respect to file size
        public static void fileImageResize(string path, string resized_path, double resize_ratio)
        {
            if (resize_ratio > 0 && resize_ratio <= 1) {
                Bitmap image = new Bitmap(path);
                double dimension_ratio = Math.Sqrt(1 / resize_ratio);
                fileImageResize(image, resized_path, (int)Math.Floor(image.Width / dimension_ratio), (int)Math.Floor(image.Height / dimension_ratio));
            }
        }
        /// Resize an image file to give new dimensions
        ///
        /// @param string path The path to the input file
        /// @param string resized_path The path to the resize file
        /// @param string width The new width
        /// @param string height The new height
        public static void fileImageResize(string path, string resized_path, int width, int height)
        {
            fileImageResize(new Bitmap(path), resized_path, width, height);
        }
        /// Resize an image file to give new dimensions
        ///
        /// @param string path The path to the input file
        /// @param string resized_path The path to the resize file
        /// @param string width The new width
        /// @param string height The new height
        public static void fileImageResize(Bitmap image, string resized_path, int width, int height)
        {
            Bitmap resized_bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using (var graphics = Graphics.FromImage(resized_bitmap))
            {
                graphics.Clear(Color.Transparent);
                graphics.CompositingQuality = CompositingQuality.HighSpeed;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.DrawImage(image, 0, 0, width, height);
            }
            string extension = resized_path.Substring(resized_path.Length - 4, 4).ToLower();
            ImageFormat image_format = ImageFormat.Jpeg;
            if (extension == ".png")
                image_format = ImageFormat.Png;
            resized_bitmap.Save(resized_path, ImageFormat.Jpeg);
        }
        /// Read the contents of a file as Base64 string
        /// 
        /// @param string string path The path to the input file
        public static string fileReadBase64(string path)
        {
            try
            {
                byte[] AsBytes = File.ReadAllBytes(path);
                return Convert.ToBase64String(AsBytes);
            }
            catch (Exception e)
            {
                return null;
            }
        }
    }
}

