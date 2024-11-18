using System;
using System.Data.SqlClient;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace MOCDIntegrations.Auth
{
    public class SqlServerAuthProvider
    {
        public async Task<ClaimsIdentity> AuthenticateUserAsync(string username, string password)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                string query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Password", password); // Note: In production, use hashed passwords

                    using (SqlDataReader reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            var identity = new ClaimsIdentity(new[]
                            {
                                new Claim(ClaimTypes.Name, username),
                                new Claim(ClaimTypes.NameIdentifier, reader["Id"].ToString()),
                                // Add more claims as needed
                            }, "ApplicationCookie");

                            return identity;
                        }
                    }
                }
            }

            return null;
        }
    }
}
