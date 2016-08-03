//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Windows;
using System.Globalization;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Configuration;
using System.Net.Http.Headers;
using System.Net;
using Newtonsoft.Json.Linq;

namespace SimpleLogin
{
    public partial class MainWindow : Window
    {
        #region Config Values
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        Uri redirectUri = new Uri(ConfigurationManager.AppSettings["ida:RedirectUri"]);
        private static string authority = aadInstance;
        private static string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];

        // GRAPH: Uncomment
        //private static string graphApiVersion = ConfigurationManager.AppSettings["ida:GraphApiVersion"];
        //private static string graphApiEndpoint = ConfigurationManager.AppSettings["ida:GraphEndpoint"];

        #endregion
        // GRAPH: Uncomment
        // private HttpClient httpClient = new HttpClient();
        private AuthenticationContext authContext = null;

        public MainWindow() {  InitializeComponent(); }


        // Checks if there are any cached tokens w/o prompting the user, if so signs in. 
        public async void CheckForCachedToken()
        {
            AuthenticationResult result = null;
            try
            {
                result = await authContext.AcquireTokenAsync(graphResourceId, clientId, redirectUri, new PlatformParameters(PromptBehavior.Never));
            }
            catch (AdalException ex)
            {
                if (ex.ErrorCode != "user_interaction_required")
                {
                    MessageBox.Show(ex.Message);
                }

                return;
            }

            SignOutButton.Visibility = Visibility.Visible;
            UserNameLabel.Content = result.UserInfo.DisplayableId;
        }

        private void SignOut(object sender = null, RoutedEventArgs args = null)
        {
            authContext.TokenCache.Clear();
            ClearCookies();

            // Reset the UI
            SignOutButton.Visibility = Visibility.Hidden;
            SignInButton.Visibility = Visibility.Visible;
            UserNameLabel.Content = string.Empty;
        }

        private async void SignIn(object sender = null, RoutedEventArgs args = null)
        {
            // CACHE: uncomment
            // authContext = new AuthenticationContext(authority, new FileCache());
            authContext = new AuthenticationContext(authority);

            // CACHE: uncomment
            // CheckForCachedToken();

            AuthenticationResult result = null;
            try
            {

                // Congrats! You can now get an Access token. 
                result = await authContext.AcquireTokenAsync(graphResourceId, clientId, redirectUri, new PlatformParameters(PromptBehavior.Always));
                
                // Reset the UI
                SignOutButton.Visibility = Visibility.Visible;
                SignInButton.Visibility = Visibility.Hidden;
                UserNameLabel.Content = "Display ID: " + result.UserInfo.DisplayableId;
            }
            catch (AdalException ex)
            {
                // An unexpected error occurred, or user canceled the sign in.
                if (ex.ErrorCode != "access_denied")
                    MessageBox.Show(ex.Message);

                return;
            }

            // GRAPH: uncomment

            //try
            //{
            //    string graphRequest = String.Format(CultureInfo.InvariantCulture, "{0}{1}/v{2}/me/", graphApiEndpoint, tenant, graphApiVersion);
            //    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, graphRequest);
            //    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            //    HttpResponseMessage response = httpClient.SendAsync(request).Result;

            //    if (!response.IsSuccessStatusCode)
            //        throw new WebException(response.StatusCode.ToString() + ": " + response.ReasonPhrase);

            //    string content = response.Content.ReadAsStringAsync().Result;
            //    JObject jResult = JObject.Parse(content);

            //    if (jResult["odata.error"] != null)
            //        throw new Exception((string)jResult["odata.error"]["message"]["value"]);

            //    // Graph Results
            //    UserNameLabel.Content += "\nGraph Result: " + jResult["value"].ToString();
            //}
            //catch (Exception ex)
            //{
            //    MessageBox.Show("Error: " + ex.Message);
            //}
        }
        #region Cookie Management

        // This function clears cookies from the browser control used by ADAL.
        private void ClearCookies()
        {
            const int INTERNET_OPTION_END_BROWSER_SESSION = 42;
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_END_BROWSER_SESSION, IntPtr.Zero, 0);
        }

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);

        #endregion
    }
}

