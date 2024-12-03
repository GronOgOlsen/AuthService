using System;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Authentication;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using NLog;
using NLog.Web;
using Authentication.Service;
using Authentication.Models;
using Microsoft.Extensions.Logging;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authentication; 

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings()
    .GetCurrentClassLogger();
logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);
    var configuration = builder.Configuration;

    BsonSerializer.RegisterSerializer(new GuidSerializer(BsonType.String));

    var vaultService = new VaultService(configuration);

    string mySecret = await vaultService.GetSecretAsync("secrets", "SecretKey") ?? "5Jw9yT4fb9T5XrwKUz23QzA5D9BuY3p6";
    string myIssuer = await vaultService.GetSecretAsync("secrets", "IssuerKey") ?? "gAdDxQDQq7UYNxF3F8pLjVmGuU5u8g3y";
    string myConnectionString = await vaultService.GetSecretAsync("secrets", "MongoConnectionString") ?? "mongodb+srv://admin:1234@4semproj.npem60f.mongodb.net/";
    
    configuration["SecretKey"] = mySecret;
    configuration["IssuerKey"] = myIssuer;

    Console.WriteLine("Issuer: " + myIssuer);
    Console.WriteLine("Secret: " + mySecret);

    string connectionString = myConnectionString;
    if (string.IsNullOrEmpty(connectionString))
    {
        logger.Error("ConnectionString not found in environment vaariables");
        throw new Exception("ConnectionString not found in environment variables");
    }
    else
    {
        logger.Info("ConnectionString: {0}", connectionString);
    }

    builder.Services.AddTransient<VaultService>();

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
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = myIssuer,
            ValidAudience = "http://localhost",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret)),
            ClockSkew = TimeSpan.Zero // remove delay of token when expire
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("Token-Expired", "true");
                    logger.Error("Token expired: {0}", context.Exception.Message);
                }
                return Task.CompletedTask;
            }
        };
    });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("UserRolePolicy", policy => policy.RequireRole("1"));
        options.AddPolicy("AdminRolePolicy", policy => policy.RequireRole("2"));
        options.AddPolicy("LegalRolePolicy", policy => policy.RequireRole("3"));
    });

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowOrigin", builder =>
        {
            builder.AllowAnyHeader()
                   .AllowAnyMethod();
        });
    });

    var userServiceUrl = Environment.GetEnvironmentVariable("userservicehost");
    if (string.IsNullOrEmpty(userServiceUrl))
    {
        logger.Error("UserServiceUrl not found in environment variables");
        throw new Exception("UserServiceUrl not found in environment variables");
    }
    else
    {
        logger.Info("UserServiceUrl: {0}", userServiceUrl);
    }

    builder.Services.AddHttpClient<IUserService, UserService>(client =>
    {
        client.BaseAddress = new Uri(userServiceUrl);
    });

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseCors("AllowOrigin");
    app.UseAuthentication(); 
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}