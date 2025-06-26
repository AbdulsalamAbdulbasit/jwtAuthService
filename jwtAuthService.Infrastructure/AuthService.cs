using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using jwtAuthService.Application.DTOs;
using jwtAuthService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace jwtAuthService.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser<Guid>> _userManager;
        private readonly SignInManager<IdentityUser<Guid>> _signInManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<IdentityUser<Guid>> userManager,
            SignInManager<IdentityUser<Guid>> signInManager,
            RoleManager<IdentityRole<Guid>> roleManager,
            ApplicationDbContext dbContext,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _dbContext = dbContext;
            _configuration = configuration;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request, string origin)
        {
            var user = new IdentityUser<Guid>
            {
                UserName = request.UserName,
                Email = request.Email,
                EmailConfirmed = false
            };
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                throw new Exception(string.Join("; ", result.Errors.Select(e => e.Description)));
            }
            // Assign default role
            if (!await _roleManager.RoleExistsAsync("User"))
                await _roleManager.CreateAsync(new IdentityRole<Guid> { Name = "User" });
            await _userManager.AddToRoleAsync(user, "User");
            // Generate email confirmation token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            // TODO: Send confirmation email with token (implement email sender)
            return new AuthResponse
            {
                UserName = user.UserName,
                Email = user.Email,
                AccessToken = string.Empty,
                RefreshToken = string.Empty
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                throw new Exception("Invalid credentials");
            if (!user.EmailConfirmed)
                throw new Exception("Email not confirmed");
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                throw new Exception("Invalid credentials");
            // Generate JWT and refresh token
            var accessToken = GenerateJwtToken(user);
            var refreshToken = Guid.NewGuid().ToString(); // TODO: Store securely and associate with user/device
            return new AuthResponse
            {
                UserName = user.UserName,
                Email = user.Email,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpires = DateTime.UtcNow.AddMinutes(5),
                RefreshTokenExpires = DateTime.UtcNow.AddDays(7)
            };
        }

        private string GenerateJwtToken(IdentityUser<Guid> user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.UserName ?? string.Empty)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // ...other methods (RefreshTokenAsync, LogoutAsync, ConfirmEmailAsync) remain as stubs for now...
    }
}

// Ensure the Infrastructure project references the Application project in your .csproj file:
// <ProjectReference Include="..\jwtAuthService.Application\jwtAuthService.Application.csproj" />
