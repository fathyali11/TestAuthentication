﻿namespace UsersManagement.DataSeeders;
public class DataSeederHostedService(IServiceProvider _serviceProvider) :IHostedService
{

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        // Ensure the database is created and migrations are applied
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        if(dbContext.Database.GetPendingMigrations().Any())
            await dbContext.Database.MigrateAsync(cancellationToken);


        if(dbContext.Roles.Any() || dbContext.Users.Any())
            return; // If roles or users already exist, skip seeding
        var _roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        // Create default admin user and it's permissions
        var adminPermissions = AdminRoleAndPermissions.GetAllPermissions();
        if (!await _roleManager.RoleExistsAsync(AdminRoleAndPermissions.Name))
            await _roleManager.CreateAsync(new IdentityRole(AdminRoleAndPermissions.Name));

        var adminRole = await _roleManager.FindByNameAsync(AdminRoleAndPermissions.Name);
        if (adminRole is null)
            await _roleManager.CreateAsync(new IdentityRole(AdminRoleAndPermissions.Name));

        foreach (var permission in adminPermissions)
            await _roleManager.AddClaimAsync(adminRole!, new Claim(AdminRoleAndPermissions.Type, permission!));

        // Create default customer user and it's permissions
        var customerPermissions = CustomerRoleAndPermissions.GetAllPermissions();
        if (!await _roleManager.RoleExistsAsync(CustomerRoleAndPermissions.Name))
            await _roleManager.CreateAsync(new IdentityRole(CustomerRoleAndPermissions.Name));

        var customerRole = await _roleManager.FindByNameAsync(CustomerRoleAndPermissions.Name);
        if (customerRole is null)
            await _roleManager.CreateAsync(new IdentityRole(CustomerRoleAndPermissions.Name));

        foreach (var permission in customerPermissions)
            await _roleManager.AddClaimAsync(customerRole!, new Claim(CustomerRoleAndPermissions.Type, permission!));

    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
