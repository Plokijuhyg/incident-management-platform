using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Role> Roles => Set<Role>();
    public DbSet<User> Users => Set<User>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<MitreTechnique> MitreTechniques => Set<MitreTechnique>();
    public DbSet<Ioc> Iocs => Set<Ioc>();
    public DbSet<IncidentNumberSequence> IncidentNumberSequences => Set<IncidentNumberSequence>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<IncidentIoc> IncidentIocs => Set<IncidentIoc>();
    public DbSet<IncidentAsset> IncidentAssets => Set<IncidentAsset>();
    public DbSet<IncidentMitreTechnique> IncidentMitreTechniques => Set<IncidentMitreTechnique>();
    public DbSet<IncidentTimelineEvent> IncidentTimelineEvents => Set<IncidentTimelineEvent>();
    public DbSet<IncidentComment> IncidentComments => Set<IncidentComment>();
    public DbSet<ResponseAction> ResponseActions => Set<ResponseAction>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new RoleConfiguration());
        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());
        modelBuilder.ApplyConfiguration(new AssetConfiguration());
        modelBuilder.ApplyConfiguration(new MitreTechniqueConfiguration());
        modelBuilder.ApplyConfiguration(new IocConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentNumberSequenceConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentConfiguration());
        modelBuilder.ApplyConfiguration(new AlertConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentIocConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentAssetConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentMitreTechniqueConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentTimelineEventConfiguration());
        modelBuilder.ApplyConfiguration(new IncidentCommentConfiguration());
        modelBuilder.ApplyConfiguration(new ResponseActionConfiguration());
        modelBuilder.ApplyConfiguration(new EvidenceConfiguration());
        modelBuilder.ApplyConfiguration(new AuditLogConfiguration());
    }
}
