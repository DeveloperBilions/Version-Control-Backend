Parse.Cloud.define("latestVersion", async (request) => {
  let { appId, platform, packageId } = request.params;

  // Validate input
  if (!appId || !platform || !packageId) {
    throw new Parse.Error(
      400,
      "Missing required parameters: appId, platform, packageId"
    );
  }

  try {
    // Create a pointer to the Applications class
    const Applications = Parse.Object.extend("Applications");
    const appPointer = new Applications();
    appPointer.id = appId;

    const Release = Parse.Object.extend("Release");
    const query = new Parse.Query(Release);

    query.equalTo("appId", appPointer);
    query.equalTo("whitelisted", true);
    query.equalTo("blacklisted", false);
    query.descending("createdAt");

    const result = await query.first();

    if (!result) {
      return { message: "No release found matching the criteria." };
    }

    return {
      version: result.get("version"),
      mandatory: result.get("mandatory"),
      whitelisted: result.get("whitelisted"),
      blacklisted: result.get("blacklisted"),
      remarks: result.get("remarks"),
      releaseNotes: result.get("releaseNotes"),
      createdAt: result.get("createdAt"),
    };
  } catch (error) {
    // Handle different error types
    if (error instanceof Parse.Error) {
      // Return the error if it's a Parse-specific error
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      // Handle any unexpected errors
      return {
        success: false,
        code: 500,
        message: "An unexpected error occurred.",
      };
    }
  }
});
