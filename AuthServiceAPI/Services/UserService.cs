using System;
using System.Net;
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

            if (userServiceResponse.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogWarning("Invalid username or password for user: {Username}", user.username);
                return null;
            }

            _logger.LogError("Unexpected response from UserService: {StatusCode}", userServiceResponse.StatusCode);
            return null;
        }

    }
}