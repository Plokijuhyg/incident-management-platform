using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace IncidentPlatform.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddAutomationPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AutomationRules",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Mode = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Version = table.Column<int>(type: "int", nullable: false),
                    CorrelationMinutes = table.Column<int>(type: "int", nullable: false),
                    OwnerId = table.Column<int>(type: "int", nullable: true),
                    ApprovedById = table.Column<int>(type: "int", nullable: true),
                    EffectiveFrom = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationRules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationRules_Users_ApprovedById",
                        column: x => x.ApprovedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AutomationRules_Users_OwnerId",
                        column: x => x.OwnerId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AutomationDecisions",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    AlertId = table.Column<int>(type: "int", nullable: false),
                    IncidentId = table.Column<int>(type: "int", nullable: true),
                    RuleId = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    PolicyVersion = table.Column<int>(type: "int", nullable: false),
                    Machine = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Outcome = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Reason = table.Column<string>(type: "varchar(1024)", maxLength: 1024, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    PolicySnapshot = table.Column<string>(type: "json", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationDecisions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationDecisions_Alerts_AlertId",
                        column: x => x.AlertId,
                        principalTable: "Alerts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AutomationDecisions_AutomationRules_RuleId",
                        column: x => x.RuleId,
                        principalTable: "AutomationRules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AutomationDecisions_Incidents_IncidentId",
                        column: x => x.IncidentId,
                        principalTable: "Incidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.InsertData(
                table: "AutomationRules",
                columns: new[] { "Id", "ApprovedById", "CorrelationMinutes", "EffectiveFrom", "Mode", "OwnerId", "UpdatedAt", "Version" },
                values: new object[,]
                {
                    { "WIN-ACCOUNT-CREATED", null, 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), "Observe", null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), 1 },
                    { "WIN-AUDIT-CLEARED", null, 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), "Observe", null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), 1 },
                    { "WIN-DEFENDER-DETECTION", null, 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), "Observe", null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), 1 },
                    { "WIN-LOCAL-GROUP-MEMBER", null, 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), "Observe", null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Utc), 1 }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationDecisions_AlertId",
                table: "AutomationDecisions",
                column: "AlertId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AutomationDecisions_IncidentId",
                table: "AutomationDecisions",
                column: "IncidentId");

            migrationBuilder.CreateIndex(
                name: "IX_AutomationDecisions_RuleId_Machine_CreatedAt",
                table: "AutomationDecisions",
                columns: new[] { "RuleId", "Machine", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRules_ApprovedById",
                table: "AutomationRules",
                column: "ApprovedById");

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRules_OwnerId",
                table: "AutomationRules",
                column: "OwnerId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AutomationDecisions");

            migrationBuilder.DropTable(
                name: "AutomationRules");
        }
    }
}
