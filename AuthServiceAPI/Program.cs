using System;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using NLog;
using NLog.Web;
using Microsoft.Extensions.Logging;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authentication;
using AuthServiceAPI.Services;
using AuthServiceAPI.Models;
using AuthServiceAPI.Interfaces;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings()
    .GetCurrentClassLogger();
logger.Debug("init main");

try
{
    // Initial setup: Configuration, Logger, and Vault
    var builder = WebApplication.CreateBuilder(args);
    var configuration = builder.Configuration;

    // Register Guid serializer for MongoDB
    BsonSerializer.RegisterSerializer(new GuidSerializer(BsonType.String)); // Konfigurerer MongoDB til at gemme GUID'er som strings.

    // Initialize Vault to retrieve secrets
    var vaultService = new VaultService(configuration);
    string mySecret = await vaultService.GetSecretAsync("secrets", "SecretKey") ?? "????";
    string myIssuer = await vaultService.GetSecretAsync("secrets", "IssuerKey") ?? "????";
    string myConnectionString = await vaultService.GetSecretAsync("secrets", "MongoConnectionString") ?? "????";

    // Add retrieved secrets to application configuration
    configuration["SecretKey"] = mySecret;
    configuration["IssuerKey"] = myIssuer;
    configuration["MongoConnectionString"] = myConnectionString;

    // Log secret details for debugging purposes
    Console.WriteLine("Issuer: " + myIssuer);
    Console.WriteLine("Secret: " + mySecret);
    Console.WriteLine("MongoConnectionString: " + myConnectionString);

    // Validate MongoDB connection string
    if (string.IsNullOrEmpty(myConnectionString))
    {
        logger.Error("ConnectionString not found in environment variables");
        throw new Exception("ConnectionString not found in environment variables");
    }
    else
    {
        logger.Info($"ConnectionString: {myConnectionString}");
    }

    // Dependency Injection: Register services
    builder.Services.AddTransient<VaultService>(); // Vault service
    builder.Services.AddControllers(); // Controllers for API endpoints
    builder.Services.AddEndpointsApiExplorer(); // Endpoint Explorer for Swagger
    builder.Services.AddSwaggerGen(); // Swagger for API documentation

    // Configure HttpClient for UserService
    var userServiceUrl = Environment.GetEnvironmentVariable("userservicehost");
    if (string.IsNullOrEmpty(userServiceUrl))
    {
        logger.Error("UserServiceUrl not found in environment variables");
        throw new Exception("UserServiceUrl not found in environment variables");
    }
    else
    {
        logger.Info($"UserServiceUrl: {userServiceUrl}");
    }

    builder.Services.AddHttpClient<IUserService, UserService>(client =>
    {
        client.BaseAddress = new Uri(userServiceUrl);
    });

    // Configure CORS
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowOrigin", builder =>
        {
            builder.AllowAnyHeader()
                   .AllowAnyMethod();
        });
    });

    // Configure JWT Authentication
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true, // Validate the token issuer
            ValidateAudience = true, // Validate the token audience
            ValidateLifetime = true, // Validate token expiry
            ValidateIssuerSigningKey = true, // Validate signing key
            ValidIssuer = myIssuer,
            ValidAudience = "http://localhost",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret)),
            ClockSkew = TimeSpan.Zero // Disable default clock skew
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("Token-Expired", "true");
                    logger.Error($"Token expired: {context.Exception.Message}");
                }
                return Task.CompletedTask;
            }
        };
    });

    // Configure Authorization Policies
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("UserRolePolicy", policy => policy.RequireRole("1")); // Policy for users
        options.AddPolicy("AdminRolePolicy", policy => policy.RequireRole("2")); // Policy for administrators
    });

    // Configure Logging
    builder.Logging.ClearProviders(); // Clear default logging providers
    builder.Host.UseNLog(); // Use NLog as the logging provider

    // Build and configure middleware pipeline
    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger(); // Enable Swagger in development environment
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection(); // Redirect HTTP to HTTPS
    app.UseCors("AllowOrigin"); // Enable configured CORS policy
    app.UseAuthentication(); // Enable JWT authentication
    app.UseAuthorization(); // Enable role-based authorization
    app.MapControllers(); // Map controllers to endpoints

    app.Run(); // Run the application
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception"); // Log any exceptions during startup
    throw;
}
finally
{
    NLog.LogManager.Shutdown(); // Properly shut down NLog
}
