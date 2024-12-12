using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthServiceAPI.Models;
using AuthServiceAPI.Interfaces;

namespace AuthServiceAPI.Services
{
    public class UserService : IUserService
    {
        private readonly HttpClient _client;
        private readonly ILogger<UserService> _logger;

        public UserService(HttpClient client, ILogger<UserService> logger)
        {
            _client = client;
            _logger = logger;
        }

        public async Task<User?> ValidateUser(LoginDTO user)
        {
            _logger.LogInformation("Validating user: {@User}", user);

            var userServiceResponse = await _client.PostAsJsonAsync("api/user/validate", user);

            if (userServiceResponse.IsSuccessStatusCode)
            {
                return await userServiceResponse.Content.ReadFromJsonAsync<User>();
            }

            _logger.LogWarning("Validation failed for user: {Username}. StatusCode: {StatusCode}", user.username, userServiceResponse.StatusCode);
            return null; // Return null hvis det ikke er en succes
        }

    }
}