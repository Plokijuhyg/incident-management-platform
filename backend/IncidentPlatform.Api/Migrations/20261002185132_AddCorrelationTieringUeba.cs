using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentPlatform.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddCorrelationTieringUeba : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CorrelationKey",
                table: "Incidents",
                type: "varchar(200)",
                maxLength: 200,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<DateTime>(
                name: "EscalatedAt",
                table: "Incidents",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "SlaDueAt",
                table: "Incidents",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Tier",
                table: "Incidents",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<string>(
                name: "EntityIp",
                table: "Alerts",
                type: "varchar(45)",
                maxLength: 45,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Host",
                table: "Alerts",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Username",
                table: "Alerts",
                type: "varchar(255)",
                maxLength: 255,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "EntityProfiles",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    EntityType = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    EntityValue = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    FirstSeenAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    EventCount = table.Column<long>(type: "bigint", nullable: false),
                    FailedLoginsHour = table.Column<int>(type: "int", nullable: false),
                    WindowStart = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    KnownSourceIpsJson = table.Column<string>(type: "json", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RiskScore = table.Column<int>(type: "int", nullable: false),
                    LastAnomaly = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    LastAnomalyAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    LastEventId = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EntityProfiles", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_CorrelationKey",
                table: "Incidents",
                column: "CorrelationKey");

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_Status_SlaDueAt",
                table: "Incidents",
                columns: new[] { "Status", "SlaDueAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_Tier_Status",
                table: "Incidents",
                columns: new[] { "Tier", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_Host",
                table: "Alerts",
                column: "Host");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_Status_IncidentId_ReceivedAt",
                table: "Alerts",
                columns: new[] { "Status", "IncidentId", "ReceivedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EntityProfiles_EntityType_EntityValue",
                table: "EntityProfiles",
                columns: new[] { "EntityType", "EntityValue" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EntityProfiles_RiskScore",
                table: "EntityProfiles",
                column: "RiskScore");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EntityProfiles");

            migrationBuilder.DropIndex(
                name: "IX_Incidents_CorrelationKey",
                table: "Incidents");

            migrationBuilder.DropIndex(
                name: "IX_Incidents_Status_SlaDueAt",
                table: "Incidents");

            migrationBuilder.DropIndex(
                name: "IX_Incidents_Tier_Status",
                table: "Incidents");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_Host",
                table: "Alerts");

            migrationBuilder.DropIndex(
                name: "IX_Alerts_Status_IncidentId_ReceivedAt",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "CorrelationKey",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "EscalatedAt",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "SlaDueAt",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "Tier",
                table: "Incidents");

            migrationBuilder.DropColumn(
                name: "EntityIp",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Host",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Username",
                table: "Alerts");
        }
    }
}
