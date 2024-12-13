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
            _client = client; // Initialiserer HttpClient for at kommunikere med UserService API.
            _logger = logger; // Logger bruges til at logge information, advarsler og fejl.
        }

        public async Task<User?> ValidateUser(LoginDTO user)
        {
            _logger.LogInformation("Validating user: {@User}", user);

            // Sender en POST-anmodning til UserService API for at validere loginoplysninger.
            var userServiceResponse = await _client.PostAsJsonAsync("api/user/validate", user);

            // Hvis anmodningen er succesfuld, læser og returnerer det validerede brugerobjekt.
            if (userServiceResponse.IsSuccessStatusCode)
            {
                return await userServiceResponse.Content.ReadFromJsonAsync<User>();
            }

            // Hvis API svarer med 404, betyder det, at brugernavn eller adgangskode er ugyldig.
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
