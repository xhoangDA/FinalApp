using Appppppp.Helper;
using FinalApp.Data;
using FinalApp.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FinalApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccController : ControllerBase
    {
        SqlConnection con = new SqlConnection();
        SqlCommand cmd = new SqlCommand();
        SqlDataReader dr;

        StudentApi _api = new StudentApi();
        SecurityController sc = new SecurityController();
        string connectStr = @"data source = NTTRUNG1; database = StudentsManagement; Integrated Security=true";


        [HttpPost("Login")]
        public async Task<IActionResult> Verify(Account acc)
        {
            SqlConnection con = new SqlConnection(connectStr);
            con.Open();
            cmd.Connection = con;
            cmd.CommandText = "select * from login where username='" + acc.Name + "' and password='" + acc.Password + "'";
            await dr = cmd.ExecuteReaderAsync();

            if (!dr.Read())
            {
                con.Close();
                return Ok(new ApiRespond 
                {
                    Success = false,
                    Message = "Invalid username/password"
                });
            }
            else
            {
                var token = await GenerateToken(acc);
                return Ok(new ApiRespond
                {
                    Success = true,
                    Message = "Authenticate success",
                    Data = token
                });
            }

        }

        //public ActionResult LogOut()
        //{
        //    HttpContext.Session.Clear();
        //    Response.Cookies.Delete("TimeSession");
        //    Response.Cookies.Delete(".AspNetCore.Session");
        //    return RedirectToAction("Login");
        //}

        private async Task<Token> GenerateToken(Account acc)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var secretKeyBytes = Encoding.UTF8.GetBytes("ppFAsv+D_`rgab!ge-='*{vx?P4>]qY2");

            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("UId", acc.ID.ToString()),
                    new Claim(JwtRegisteredClaimNames.UniqueName,acc.Name)

                //thieu role

            }),
                Expires = DateTime.UtcNow.AddSeconds(20),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha512Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescription);

            var accessToken = jwtTokenHandler.WriteToken(token);
            var refreshToken = GenerateRefreshToken();

            //Luu ft vao database

            var refreshTokenEntity = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = acc.ID,
                JwtId = token.Id,
                Token = refreshToken,
                IsUsed = false,
                IsRevoked = false,
                IssuedAt = DateTime.UtcNow,
                ExpriredAt = DateTime.UtcNow.AddHours(1)
            };

            string AddRefreshTokenSql = "INSERT INTO RefeshToken(Id, UserId, JwtId, Token, IsUsed, IsRevoked, IssuedAt, ExpriredAt) VALUES('" + refreshTokenEntity.Id +
                "','" + acc.ID + "', '" + token.Id + "', '" + refreshToken + "', '" + refreshTokenEntity.IsUsed + "', '" + refreshTokenEntity.IsRevoked
                + "', '" + refreshTokenEntity.IssuedAt + "', '" + refreshTokenEntity.ExpriredAt + "');";

            SqlConnection con = new SqlConnection(connectStr);
            cmd = new SqlCommand(AddRefreshTokenSql, con);
            con.Open();
            await cmd.ExecuteNonQueryAsync();
            cmd.Dispose();
            con.Close();

            return new Token
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        private string GenerateRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);

                return Convert.ToBase64String(random);
            }
        }

        [HttpPost("RenewToken")]
        public async Task<IActionResult> RenewToken(Token model)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = Encoding.UTF8.GetBytes("ppFAsv+D_`rgab!ge-='*{vx?P4>]qY2");
            var tokenValidateParam = new TokenValidationParameters()
            {
                //tu cap token
                ValidateIssuer = false,
                ValidateAudience = false,

                //ky tao token
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secretKeyBytes),

                ClockSkew = TimeSpan.Zero,

                ValidateLifetime = false
            };

            try
            {
                //check 1: AccessToken valid format?
                SqlConnection con = new SqlConnection(connectStr);
                var tokenInVerification = jwtTokenHandler.ValidateToken(model.AccessToken, tokenValidateParam, out var validatedToken);

                //check 2: Check Algorithm
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCultureIgnoreCase);
                    if (!result)
                    {
                        return Ok(new ApiRespond
                        {
                            Success = false,
                            Message = "Invalid Token"
                        });
                    }

                }

                //check 3: Check accessToken expire?
                var utcExpireDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                var expireDate = ConvertUnixTimeToDateTime(utcExpireDate);

                if (expireDate > DateTime.UtcNow)
                {
                    return Ok(new ApiRespond
                    {
                        Success = false,
                        Message = "Access token has not yet expired."
                    });
                }

                //check 4: Rt exist in DB?
                string selectSql = "SELECT * FROM RefreshToken WHERE Token = " + model.RefreshToken;
                DataTable dt = new DataTable();

                SqlDataAdapter da = new SqlDataAdapter(selectSql, con);
                con.Open();
                da.Fill(dt);
                da.Dispose();
                con.Close();

                if (dt == null)
                {
                    return Ok(new ApiRespond
                    {
                        Success = false,
                        Message = "Refresh token does not exist in DB."
                    });
                }

                if (dt != null)
                {
                    var storedToken = new RefreshToken();
                    storedToken.Id = (Guid)dt.Rows[0]["ID"];
                    storedToken.UserId = Convert.ToInt32(dt.Rows[0]["UserId"].ToString());
                    storedToken.Token = dt.Rows[0]["Token"].ToString();
                    storedToken.JwtId = dt.Rows[0]["JwtId"].ToString();
                    storedToken.IsUsed = Convert.ToBoolean(dt.Rows[0]["IsUsed"].ToString());
                    storedToken.IsRevoked = Convert.ToBoolean(dt.Rows[0]["IsRevoked"].ToString());
                    storedToken.IssuedAt = (DateTime)dt.Rows[0]["IssuedAt"];
                    storedToken.ExpriredAt = (DateTime)dt.Rows[0]["ExpriredAt"];

                    //check 5: rt is used/revoked?
                    if (storedToken.IsUsed)
                    {
                        return Ok(new ApiRespond
                        {
                            Success = false,
                            Message = "Refresh token has been used."
                        });
                    }
                    if (storedToken.IsRevoked)
                    {
                        return Ok(new ApiRespond
                        {
                            Success = false,
                            Message = "Refresh token has been revoked."
                        });
                    }

                    //check 6: AccessToken == JwtID in RefreshToken?
                    var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                    if (storedToken.JwtId != jti)
                    {
                        return Ok(new ApiRespond
                        {
                            Success = false,
                            Message = "Token doesn't match."
                        });
                    }

                    //Update token is used
                    storedToken.IsRevoked = true;
                    storedToken.IsUsed = true;

                    string addToDbSql = @"INSERT INTO RefeshToken(Id, UserId, JwtId, Token, IsUsed, IsRevoked, IssuedAt, ExpriredAt) VALUES('" + storedToken.Id +
                        "','" + storedToken.UserId + "', '" + storedToken.JwtId + "', '" + storedToken.Token + "', '" + storedToken.IsUsed + "', '" + storedToken.IsRevoked
                        + "', '" + storedToken.IssuedAt + "', '" + storedToken.ExpriredAt + "');";

                    SqlCommand addRefreshToken = new SqlCommand(addToDbSql, con);
                    con.Open();
                    await addRefreshToken.ExecuteNonQueryAsync();
                    addRefreshToken.Dispose();
                    con.Close();


                    //Cretate renew token

                    var user = new Account();
                    string getUserSql = "SELECT * FROM login WHERE id = " + storedToken.UserId;
                    SqlCommand getUserAccount = new SqlCommand(getUserSql, con);
                    con.Open();
                    await getUserAccount.ExecuteNonQueryAsync();
                    getUserAccount.Dispose();
                    con.Close();

                    var token = await GenerateToken(user);

                    return Ok(new ApiRespond
                    {
                        Success = true,
                        Message = "Renew token successful",
                        Data = token
                    });
                }
                else return BadRequest(new ApiRespond
                {
                    Success = false,
                    Message = "Error occured"
                });

            }
            catch (Exception ex)
            {
                return BadRequest(new ApiRespond
                {
                    Success = false,
                    Message = ex.ToString()
                });
            }
        }

        private DateTime ConvertUnixTimeToDateTime(long utcExpireDate)
        {
            var dateTimeInterval = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeInterval.AddSeconds(utcExpireDate).ToUniversalTime();

            return dateTimeInterval;
        }
    }
}
