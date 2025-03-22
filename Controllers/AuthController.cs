using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http.Headers;
using System.Text;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly HttpClient _httpClient;

    public AuthController(IConfiguration config)
    {
        _config = config;
        _httpClient = new HttpClient();
    }


    [HttpGet("login/facebook")]
    public IActionResult GetFacebookLoginUrl()
    {
        var auth0Domain = _config["Auth0:Domain"];
        var clientId = _config["Auth0:ClientId"];
        var redirectUri = Uri.EscapeDataString(_config["Auth0:CallbackUrl"]);
        var audience = Uri.EscapeDataString(_config["Auth0:Audience"]);

        var authUrl = $"https://{auth0Domain}/authorize" +
                        $"?response_type=code" +
                        $"&client_id={clientId}" +
                        $"&redirect_uri={redirectUri}" +
                        $"&scope=openid profile email offline_access" +
                        $"&audience={audience}" +
                        $"&connection=facebook";

        return Ok(authUrl);
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        var auth0Domain = _config["Auth0:Domain"];
        var clientId = _config["Auth0:ClientId"];
        var redirectUri = _config["Auth0:CallbackUrl"];
        var audience = _config["Auth0:Audience"];
        var scope = "openid profile email";

        var authorizeUrl = $"https://{auth0Domain}/authorize?" +
                      $"response_type=code&" +
                      $"client_id={clientId}&" +
                      $"redirect_uri={redirectUri}&" +
                      $"scope={scope}&" +
                      $"audience={audience}&" +
                      $"prompt=login";

        return Ok(authorizeUrl);
    }

    [HttpPost("sign-up")]
    public async Task<IActionResult> SignUp([FromBody] SignUpRequest request)
    {
        var values = new Dictionary<string, string>
    {
        { "client_id", _config["Auth0:ClientId"] },
        { "client_secret", _config["Auth0:ClientSecret"] },
        { "email", request.Email },
        { "password", request.Password },
        { "connection", "Username-Password-Authentication" },
    };

        var content = new StringContent(JsonConvert.SerializeObject(values), Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync($"https://{_config["Auth0:Domain"]}/dbconnections/signup", content);
        var responseString = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            return BadRequest(responseString);
        }

        return Ok(responseString);
    }


    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return BadRequest(new { error = "Authorization code is missing" });
        }

        var values = new Dictionary<string, string>
    {
        { "grant_type", "authorization_code" },
        { "client_id", _config["Auth0:ClientId"] },
        { "client_secret", _config["Auth0:ClientSecret"] },
        { "code", code },
        { "redirect_uri", _config["Auth0:CallbackUrl"] },
        { "audience", _config["Auth0:Audience"] }
    };

        var content = new FormUrlEncodedContent(values);

        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_config["Auth0:Domain"]}/oauth/token")
        {
            Content = content
        };

       
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        var response = await _httpClient.SendAsync(request);
        var responseString = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            return BadRequest(new
            {
                error = "Failed to exchange code for token",
                status = response.StatusCode,
                details = responseString
            });
        }

        JObject json = JObject.Parse(responseString);
        Console.WriteLine(responseString);
        return Ok(new
        {
            AccessToken = json["access_token"]?.ToString(),
            IdToken = json["id_token"]?.ToString(),
            RefreshToken = json["refresh_token"]?.ToString(),
            tokenType = json["token_type"]?.ToString(),
            expiresIn = json["expires_in"]?.ToObject<int>() ?? 0,
        });
    }

    [HttpGet("profile")]
    public async Task<IActionResult> GetUserProfile([FromQuery] string accessToken) { 

        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, $"https://{_config["Auth0:Domain"]}/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var userInfoResponse = await _httpClient.SendAsync(userInfoRequest);
        var userInfoString = await userInfoResponse.Content.ReadAsStringAsync();

        
        if (!userInfoResponse.IsSuccessStatusCode)
        {
            return BadRequest(new
            {
                error = "Failed to fetch user info",
                status = userInfoResponse.StatusCode,
                details = userInfoString
            });
        }

        JObject json = JObject.Parse(userInfoString);
        return Ok(new
        {
            Sub = json["sub"]?.ToString(),
            GivenName = json["given_name"]?.ToString(),
            FamilyName = json["family_name"]?.ToString(),
            MiddleName = json["middle_name"]?.ToString(),
            Nickname = json["nickname"]?.ToString(),
            Name = json["name"]?.ToString(),
            Picture = json["picture"]?.ToString(),
            UpdatedAt = json["updated_at"]?.ToString(),
            Email = json["email"]?.ToString(),
            EmailVerified = json["email_verified"]?.ToObject<bool>() ?? false
        });
    }



    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
    {
        var values = new Dictionary<string, string>
            {
                { "client_id", _config["Auth0:ClientId"] },
                { "client_secret", _config["Auth0:ClientSecret"] },
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            };

        var content = new FormUrlEncodedContent(values);
        var response = await _httpClient.PostAsync($"https://{_config["Auth0:Domain"]}/oauth/token", content);
        var responseString = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            return BadRequest(responseString);
        }

        JObject json = JObject.Parse(responseString);
        return Ok(new
        {
            AccessToken = json["access_token"]?.ToString(),
            IdToken = json["id_token"]?.ToString(),
            RefreshToken = json["refresh_token"]?.ToString(),
            tokenType = json["token_type"]?.ToString(),
            expiresIn = json["expires_in"]?.ToObject<int>() ?? 0,
        });
    }


    [HttpGet("logout")]
    public IActionResult Logout()
    {
        string logoutUrl = $"https://{_config["Auth0:Domain"]}/v2/logout?client_id={_config["Auth0:ClientId"]}&returnTo={_config["Auth0:CallbackUrl"]}";
        return Redirect(logoutUrl);
    }


    [HttpPost("revoke")]
    public async Task<IActionResult> RevokeToken([FromBody] string token)
    {
        var values = new Dictionary<string, string>
            {
                { "client_id", _config["Auth0:ClientId"] },
                { "client_secret", _config["Auth0:ClientSecret"] },
                { "token", token }
            };

        var content = new FormUrlEncodedContent(values);
        var response = await _httpClient.PostAsync($"https://{_config["Auth0:Domain"]}/oauth/revoke", content);
        var responseString = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            return BadRequest(responseString);
        }

        return Ok(new { message = "Token revoked successfully" });
    }
}


public class TokenExchangeRequest
{
    public string SubjectToken { get; set; }
}
public class SignUpRequest
{
    public string Email { get; set; }
    public string Password { get; set; }
}
