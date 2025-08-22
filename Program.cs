using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication;

using IAuthenticationService = EntraApiAuth.Services.IAuthenticationService;
using AuthenticationService = EntraApiAuth.Services.AuthenticationService;

var builder = WebApplication.CreateBuilder(args);

//add service -> controller
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//configure authentication in microsoft entra id
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

//add cors
builder.Services.AddCors(o =>
{
    o.AddPolicy("AllowSpesificOrigin",
//b => b.WithOrigins("*")
//    .WithMethods("GET", "POST")
//    .WithHeaders("Authorization", "Content-Type")
//    .AllowCredentials());
b => b.WithOrigins("*")
 .WithMethods("GET", "POST")
 .WithHeaders("Authorization", "Content-Type"));


});

builder.Services.AddSingleton<IConfidentialClientApplication>(p =>
{
    var config = p.GetRequiredService<IConfiguration>();
    return ConfidentialClientApplicationBuilder
        .Create(config["AzureAd:ClientId"])
        .WithClientSecret(config["AzureAd:ClientSecret"])
        .WithAuthority(new Uri($"{config["AzureAd:Instance"]}/{config["AzureAd:TenantId"]}"))
        .Build();
});

builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddHttpClient();

//set cache response
builder.Services.AddResponseCaching();

//set memory cache buffer for token
builder.Services.AddMemoryCache();

var app = builder.Build();

//check isdevelopment http request
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowSpesificOrigin");
app.UseResponseCaching();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();