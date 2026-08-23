using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentPlatform.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddIncidentJoinTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IncidentAssets",
                columns: table => new
                {
                    IncidentId = table.Column<int>(type: "int", nullable: false),
                    AssetId = table.Column<int>(type: "int", nullable: false),
                    ImpactType = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Notes = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    AddedById = table.Column<int>(type: "int", nullable: false),
                    AddedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IncidentAssets", x => new { x.IncidentId, x.AssetId });
                    table.ForeignKey(
                        name: "FK_IncidentAssets_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IncidentAssets_Incidents_IncidentId",
                        column: x => x.IncidentId,
                        principalTable: "Incidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_IncidentAssets_Users_AddedById",
                        column: x => x.AddedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "IncidentIocs",
                columns: table => new
                {
                    IncidentId = table.Column<int>(type: "int", nullable: false),
                    IocId = table.Column<int>(type: "int", nullable: false),
                    Role = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Notes = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    AddedById = table.Column<int>(type: "int", nullable: false),
                    AddedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IncidentIocs", x => new { x.IncidentId, x.IocId });
                    table.ForeignKey(
                        name: "FK_IncidentIocs_Incidents_IncidentId",
                        column: x => x.IncidentId,
                        principalTable: "Incidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_IncidentIocs_Iocs_IocId",
                        column: x => x.IocId,
                        principalTable: "Iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IncidentIocs_Users_AddedById",
                        column: x => x.AddedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "IncidentMitreTechniques",
                columns: table => new
                {
                    IncidentId = table.Column<int>(type: "int", nullable: false),
                    MitreTechniqueId = table.Column<int>(type: "int", nullable: false),
                    Notes = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    AddedById = table.Column<int>(type: "int", nullable: false),
                    AddedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IncidentMitreTechniques", x => new { x.IncidentId, x.MitreTechniqueId });
                    table.ForeignKey(
                        name: "FK_IncidentMitreTechniques_Incidents_IncidentId",
                        column: x => x.IncidentId,
                        principalTable: "Incidents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_IncidentMitreTechniques_MitreTechniques_MitreTechniqueId",
                        column: x => x.MitreTechniqueId,
                        principalTable: "MitreTechniques",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IncidentMitreTechniques_Users_AddedById",
                        column: x => x.AddedById,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentAssets_AddedById",
                table: "IncidentAssets",
                column: "AddedById");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentAssets_AssetId",
                table: "IncidentAssets",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentIocs_AddedById",
                table: "IncidentIocs",
                column: "AddedById");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentIocs_IocId",
                table: "IncidentIocs",
                column: "IocId");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentMitreTechniques_AddedById",
                table: "IncidentMitreTechniques",
                column: "AddedById");

            migrationBuilder.CreateIndex(
                name: "IX_IncidentMitreTechniques_MitreTechniqueId",
                table: "IncidentMitreTechniques",
                column: "MitreTechniqueId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IncidentAssets");

            migrationBuilder.DropTable(
                name: "IncidentIocs");

            migrationBuilder.DropTable(
                name: "IncidentMitreTechniques");
        }
    }
}
