namespace jwtAuthService.Application
{
    public class Class1
    {

    }
}

namespace jwtAuthService.Application.DTOs
{
    public class RegisterRequest
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string DeviceFingerprint { get; set; }
    }

    public class AuthResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime AccessTokenExpires { get; set; }
        public DateTime RefreshTokenExpires { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
        public string DeviceFingerprint { get; set; }
    }
}
