namespace UsersManagement;

public static class DI
{
    public static void AddSerilogLogging(this WebApplicationBuilder builder)
    {
        builder.Host.UseSerilog((context, services, configuration) =>
        {
            configuration
                .ReadFrom.Configuration(context.Configuration)
                .ReadFrom.Services(services);
        });
    }
    public static void AddDataSeederHostedService(this WebApplicationBuilder builder)
    {
        builder.Services.AddHostedService<DataSeeders.DataSeederHostedService>();
    }

    public static void AddRateLimiterService(this WebApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.AddFixedWindowLimiter("fixed", fixedOptions =>
            {
                fixedOptions.PermitLimit = 4;
                fixedOptions.Window = TimeSpan.FromMinutes(1);
                fixedOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                fixedOptions.QueueLimit = 0;
                fixedOptions.AutoReplenishment = true;
            });

            options.OnRejected = async (context, token) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync("Too Many Requests");
            };
        });
    }

    public static void AddHybridCacheService(this WebApplicationBuilder builder)
    {
        builder.Services.AddHybridCache();
    }

    public static void AddControllersAndSwagger(this WebApplicationBuilder builder)
    {
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
    }

    public static void AddJwtOptions(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<JwtConfig>()
            .Bind(builder.Configuration.GetSection(nameof(JwtConfig)))
            .ValidateOnStart();
    }

    public static void AddGoogleOptions(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<GoogleConfig>()
            .Bind(builder.Configuration.GetSection(nameof(GoogleConfig)))
            .ValidateOnStart();
    }

    public static void AddDbContextService(this WebApplicationBuilder builder)
    {
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
    }

    public static void AddIdentityServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = true;
            options.Lockout.AllowedForNewUsers = true;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.MaxFailedAccessAttempts = 5;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();
    }

    public static void AddAuthenticationServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = "MyCookieAuth";
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddCookie("MyCookieAuth", options =>
        {
            options.LoginPath = "/api/auth/external-login";
            options.LogoutPath = "/logout";
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
        })
        .AddGoogle(options =>
        {
            options.ClientId = builder.Configuration["GoogleConfig:ClientId"]!;
            options.ClientSecret = builder.Configuration["GoogleConfig:ClientSecret"]!;
            options.SignInScheme = "MyCookieAuth";
            options.SaveTokens = true;
        });
    }

    public static void AddEmailOptions(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<EmailSettings>()
            .Bind(builder.Configuration.GetSection(nameof(EmailSettings)))
            .ValidateOnStart();
    }

    public static void AddAppScopedServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped<IAuthServices, AuthServices>();
        builder.Services.AddScoped<IEmailService, EmailService>();
        builder.Services.AddScoped<ValidationService>();
        builder.Services.AddMapster();
        UserMapping.ConfigMapping();

        builder.Services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();
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
        builder.Services.AddScoped<IValidator<ChangeStatusOfUserAccountRequest>, ChangeStatusOfUserAccountRequestValidator>();
        //builder.Services.AddHostedService<DataSeederHostedService>();
        builder.Services.AddScoped<BlobStorageServices>();
    }

    public static void AddHangfireServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddHangfire(config => config
            .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseSqlServerStorage(builder.Configuration.GetConnectionString("HangfireConnection")));

        builder.Services.AddHangfireServer();
    }

    public static void AddProjectServices(this WebApplicationBuilder builder)
    {
        builder.AddDataSeederHostedService();
        builder.AddSerilogLogging();
        builder.AddRateLimiterService();
        builder.AddHybridCacheService();
        builder.AddControllersAndSwagger();
        builder.AddJwtOptions();
        builder.AddGoogleOptions();
        builder.AddDbContextService();
        builder.AddIdentityServices();
        builder.AddAuthenticationServices();
        builder.AddEmailOptions();
        builder.AddAppScopedServices();
        builder.AddHangfireServices();
    }
}