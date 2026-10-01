namespace IncidentPlatform.Api.DTOs.Dashboard;

public record DashboardSummary(int TotalIncidents, int OpenIncidents, int CriticalOpenIncidents,
    int UnassignedIncidents, int NewAlerts, int IncidentsCreatedToday, int MyOpenIncidents);
public record CountBucket(string Label, int Count);
public record TimeBucket(DateTime Start, int Count);
public record TechniqueCount(string TechniqueId, string Name, int Count);
public record DashboardMetrics(double? MeanTimeToDetectMinutes, double? MeanTimeToContainMinutes,
    double? MeanTimeToResolveMinutes, int SampleSize, int PeriodDays,
    int DetectionSampleSize, int ContainmentSampleSize, int ResolutionSampleSize);
