using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

public partial class AppDbContext : DbContext
{
    private readonly IncidentPlatform.Api.Interfaces.IAuditContext? _audit;

    public AppDbContext(DbContextOptions<AppDbContext> options, IncidentPlatform.Api.Interfaces.IAuditContext? audit = null) : base(options)
    {
        _audit = audit;
    }

    public DbSet<IncidentNotification> IncidentNotifications => Set<IncidentNotification>();
    public DbSet<DetectionRule> DetectionRules => Set<DetectionRule>();
    public DbSet<AutomationRule> AutomationRules => Set<AutomationRule>();
    public DbSet<AutomationDecision> AutomationDecisions => Set<AutomationDecision>();
    public DbSet<SecurityAssessment> SecurityAssessments => Set<SecurityAssessment>();
    public DbSet<WindowsEvent> WindowsEvents => Set<WindowsEvent>();
    public DbSet<WindowsEventCheckpoint> WindowsEventCheckpoints => Set<WindowsEventCheckpoint>();
    public DbSet<LogEvent> LogEvents => Set<LogEvent>();
    public DbSet<EntityProfile> EntityProfiles => Set<EntityProfile>();

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
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfiguration(new IncidentNotificationConfiguration());
        modelBuilder.ApplyConfiguration(new DetectionRuleConfiguration());
        modelBuilder.ApplyConfiguration(new AutomationRuleConfiguration());
        modelBuilder.ApplyConfiguration(new AutomationDecisionConfiguration());
        modelBuilder.ApplyConfiguration(new SecurityAssessmentConfiguration());
        modelBuilder.ApplyConfiguration(new WindowsEventConfiguration());
        modelBuilder.ApplyConfiguration(new WindowsEventCheckpointConfiguration());
        modelBuilder.ApplyConfiguration(new LogEventConfiguration());
        modelBuilder.ApplyConfiguration(new EntityProfileConfiguration());

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
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
    }
}
