namespace AuthServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthServiceAPIController : ControllerBase
    {
        private readonly ILogger<AuthServiceAPIController> _logger;
        private readonly IConfiguration _config;
        private readonly VaultService _vaultService;
        private readonly IUserService _userService;
        private static readonly Logger _nLogger = LogManager.GetCurrentClassLogger();
        private string secret;
        private string issuer;

        public AuthServiceAPIController(ILogger<AuthServiceAPIController> logger, IConfiguration config, VaultService vault, IUserService userService)
        {
            _config = config;
            _logger = logger;
            _vaultService = vault;
            _userService = userService;

            // Henter SecretKey og IssuerKey fra Vault-konfigurationen.
            secret = config["SecretKey"] ?? "noSecret";
            issuer = config["IssuerKey"] ?? "noIssuer";
        }

        private string GenerateJwtToken(string username, string issuer, string secret, int role, Guid _id)
        {
            // Genererer en JWT-token med claims for brugernavn, rolle og bruger-ID.
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim("username", username),
                new Claim(ClaimTypes.Role, role.ToString()),
                new Claim("_id", _id.ToString())
            };

            var token = new JwtSecurityToken(
                issuer,
                "http://localhost/",
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);

            _logger.LogInformation("Genereret token: {0}", new JwtSecurityTokenHandler().WriteToken(token));
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost("loginuser")]
        public async Task<IActionResult> LoginUser([FromBody] LoginDTO user)
        {
            // Håndterer login for almindelige brugere (rolle 1).
            _logger.LogInformation("Forsøger at logge bruger ind: {Username}", user.username);

            var validUser = await _userService.ValidateUser(user);

            if (validUser == null)
            {
                _logger.LogWarning("Ugyldigt brugernavn eller adgangskode: {Username}", user.username);
                return Unauthorized("Ugyldigt brugernavn eller adgangskode.");
            }

            if (validUser.role == 1)
            {
                var token = GenerateJwtToken(validUser.username, issuer, secret, 1, validUser._id);
                LogIPAddress();
                _logger.LogInformation("Bruger {Username} logget ind med succes", user.username);
                return Ok(new { token });
            }

            // Afviser login, hvis rollen er ugyldig.
            _logger.LogWarning("Ugyldig rolle for bruger {Username}. Forventede rolle 1, men fik {Role}.", user.username, validUser.role);
            return Unauthorized("Ugyldig rolle for bruger.");
        }

        [AllowAnonymous]
        [HttpPost("loginadmin")]
        public async Task<IActionResult> LoginAdmin([FromBody] LoginDTO user)
        {
            // Håndterer login for administratorer (rolle 2).
            _logger.LogInformation("Forsøger at logge admin-bruger ind: {Username}", user.username);

            var validUser = await _userService.ValidateUser(user);

            if (validUser == null)
            {
                _logger.LogWarning("Ugyldigt brugernavn eller adgangskode: {Username}", user.username);
                return Unauthorized("Ugyldigt brugernavn eller adgangskode.");
            }

            if (validUser.role == 2)
            {
                var token = GenerateJwtToken(validUser.username, issuer, secret, 2, validUser._id);
                LogIPAddress();
                _logger.LogInformation("Admin-bruger {Username} logget ind med succes", user.username);
                return Ok(new { token });
            }

            // Afviser login, hvis rollen er ugyldig.
            _logger.LogWarning("Ugyldig rolle for bruger {Username}. Forventede rolle 2, men fik {Role}.", user.username, validUser.role);
            return Unauthorized("Ugyldig rolle for bruger.");
        }

        private void LogIPAddress()
        {
            // Logger IP-adressen for AuthServiceAPI-tjenesten.
            var hostName = System.Net.Dns.GetHostName();
            var ips = System.Net.Dns.GetHostAddresses(hostName);
            var ipAddr = ips.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();

            if (!string.IsNullOrEmpty(ipAddr))
            {
                _logger.LogInformation($"AuthServiceAPI svarer fra IP: {ipAddr}");
                _nLogger.Info($"AuthServiceAPI svarer fra IP: {ipAddr}");
            }
            else
            {
                _logger.LogWarning("Kunne ikke hente IP-adressen.");
                _nLogger.Warn("Kunne ikke hente IP-adressen.");
            }
        }
    }
}
