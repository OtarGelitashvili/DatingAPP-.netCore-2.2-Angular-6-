using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;

        public AuthController(IAuthRepository repo,IConfiguration config,IMapper mapper)
        {
            _mapper = mapper;
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            userForRegisterDto.userName=userForRegisterDto.userName.ToLower();
            if(await _repo.UserExists( userForRegisterDto.userName )) {
                return BadRequest( "Username already exists" );
            }
            var UserToCreate=_mapper.Map<User>(userForRegisterDto);
            var createdUser=await _repo.Register(UserToCreate,userForRegisterDto.Password);
            var userToReturn=_mapper.Map<UserForDetailedDto>(createdUser);
            return CreatedAtRoute("GetUSer",new {Controller="Users",id="createdUser.Id"},userToReturn);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo=await _repo.Login(userForLoginDto.userName,userForLoginDto.Password);
                if(userFromRepo==null) {
                    return Unauthorized();
                }
            var claims =new[]{
                new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name,userFromRepo.userName)
            };
            var key= new SymmetricSecurityKey(Encoding.UTF8.GetBytes
                (_config.GetSection("AppSettings:Token").Value));

            var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

            var tokenDescription =new SecurityTokenDescriptor 
            {
                Subject= new ClaimsIdentity(claims),
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials=creds
            };
            var tokenHandler=new JwtSecurityTokenHandler();

            var token=tokenHandler.CreateToken(tokenDescription);
            
            var user=_mapper.Map<UserForListDto>(userFromRepo);
            return Ok( new{
                token=tokenHandler.WriteToken(token),
                user
            });

         }
    }
}