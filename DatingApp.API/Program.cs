using System;
using DatingApp.API.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace DatingApp.API
{
    public class Program
    {
        public static void Main(string[] args)
        {
           var host=CreateWebHostBuilder(args).Build();
           using(var scope=host.Services.CreateScope()){
               var Services=scope.ServiceProvider;
               try {
                   var context=Services.GetRequiredService<DataContext>();
                   context.Database.Migrate();
                   Seed.SeedUsers(context);
               }
               catch(Exception e){
                   var logger=Services.GetRequiredService<ILogger<Program>>();
                   logger.LogError(e, "An error occured during migration");
               }
           }
           host.Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>();
    }
}
