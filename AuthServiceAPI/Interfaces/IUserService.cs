using AuthServiceAPI.Models;

namespace AuthServiceAPI.Interfaces
{
    public interface IUserService
    {
        Task<User> ValidateUser(LoginDTO user);
    }
}