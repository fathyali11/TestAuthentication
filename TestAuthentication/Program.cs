using FluentValidation;
using Hangfire;
using Mapster;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using System.Text;
using TestAuthentication.Constants;
using TestAuthentication.CustomValidations;
using TestAuthentication.Data;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.Mappings;
using TestAuthentication.Models;
using TestAuthentication.Services.AuthService;
using TestAuthentication.Services.BlobStorage;
using TestAuthentication.Services.EmailServices;
using TestAuthentication.Services.General;
using TestAuthentication.Services.UserServices;


var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services);
});
// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Test Authentication", Version = "v1" });

    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        Scheme = "bearer",
        BearerFormat = "JWT",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Description = "Enter JWT Bearer token",

        Reference = new OpenApiReference
        {
            Id = "Bearer",
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition("Bearer", jwtSecurityScheme);

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            jwtSecurityScheme,
            Array.Empty<string>()
        }
    });
});

// Configure JWT authentication
builder.Services.AddOptions<JwtConfig>()
    .Bind(builder.Configuration.GetSection(nameof(JwtConfig)))
    .ValidateOnStart();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;

})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme=JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        var jwtConfig = builder.Configuration.GetSection(nameof(JwtConfig)).Get<JwtConfig>();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtConfig!.Issuer,
            ValidAudience = jwtConfig.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Key))
        };

    } ) ;

builder.Services.AddOptions<EmailSettings>()
    .Bind(builder.Configuration.GetSection(nameof(EmailSettings)))
    .ValidateOnStart();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IAuthServices, AuthServices>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ValidationService>();
builder.Services.AddMapster();
UserMapping.ConfigMapping();

builder.Services.AddScoped<IValidator<RegisterRequest>,RegisterRequestValidator>();
builder.Services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddScoped<IValidator<ConfirmEmailRequest>, ConfirmEmailRequestValidator>();
builder.Services.AddScoped<IValidator<ForgetPasswordRequest>, ForgetPasswordRequestValidator>();
builder.Services.AddScoped<IValidator<ResetPasswordRequest>, ResetPasswordRequestValidator>();
builder.Services.AddScoped<IValidator<ResendEmailConfirmationRequest>, ResendEmailConfirmationRequestValidator>();
builder.Services.AddScoped<IValidator<AddToRoleRequest>, AddToRoleRequestValidator>();
builder.Services.AddScoped<IValidator<ChangePasswordRequest>, ChangePasswordRequestValidator>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IValidator<UpdateProfileRequest>, UpdateProfileRequestValidator>();
builder.Services.AddScoped<IValidator<UpdateProfilePictureRequest>, UpdateProfilePictureRequestValidator>();
//builder.Services.AddHostedService<DataSeederHostedService>();

builder.Services.AddScoped<BlobStorageServices>();
builder.Services.AddHangfire(config => config
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(builder.Configuration.GetConnectionString("HangfireConnection")));

builder.Services.AddHangfireServer();

var app = builder.Build();



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.MapStaticAssets();
app.UseSerilogRequestLogging();
app.UseHttpsRedirection();

app.UseAuthorization();
app.UseHangfireDashboard("/hangfire");

app.MapControllers();

app.Run();
