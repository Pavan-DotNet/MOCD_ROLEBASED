using System;
using System.Data.SqlClient;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using System.Security.Cryptography;
using Microsoft.AspNet.Identity;

namespace MOCDIntegrations.Auth
{
    public class SqlServerAuthProvider
    {
        public async Task<ClaimsIdentity> AuthenticateUserAsync(string username, string password)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;

            try
            {
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand("sp_AuthenticateUser", connection))
                    {
                        command.CommandType = System.Data.CommandType.StoredProcedure;
                        command.Parameters.AddWithValue("@Username", username);

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                string storedHash = reader["PasswordHash"].ToString();
                                string storedSalt = reader["PasswordSalt"].ToString();

                                if (VerifyPassword(password, storedHash, storedSalt))
                                {
                                    var identity = new ClaimsIdentity(new[]
                                    {
                                        new Claim(ClaimTypes.Name, username),
                                        new Claim(ClaimTypes.NameIdentifier, reader["Id"].ToString()),
                                        new Claim(ClaimTypes.Role, reader["Role"].ToString()),
                                    }, "ApplicationCookie");

                                    return identity;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"An error occurred: {ex.Message}");
            }

            return null;
        }

        private bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            byte[] salt = Convert.FromBase64String(storedSalt);
            string computedHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return computedHash == storedHash;
        }
    }
}
