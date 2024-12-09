using MongoDB.Bson.Serialization.Attributes;


namespace AuthServiceAPI.Models
{
    public class User
    {
        [BsonId]
        public Guid _id { get; set; }
        public string? firstName { get; set; }
        public string? lastName { get; set; }
        public string? email { get; set; }

        public string? address { get; set; }

        public string? telephonenumber { get; set; }

        public int? role { get; set; } = 1;

        public string? username { get; set; }

        public string? password { get; set; }

        public User(string firstName, string lastName, string email, string address, string telephonenumber, int role, string username, string password)
        {
            this.firstName = firstName;
            this.lastName = lastName;
            this.email = email;
            this.address = address;
            this.telephonenumber = telephonenumber;
            this.role = role;
            this.username = username;
            this.password = password;
        }
        public User()
        {
        }
    }
} 