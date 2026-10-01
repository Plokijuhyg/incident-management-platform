using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentPlatform.Api.Migrations
{
    /// <inheritdoc />
    public partial class AddAssessmentSelection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RequestJson",
                table: "SecurityAssessments",
                type: "json",
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RequestJson",
                table: "SecurityAssessments");
        }
    }
}
