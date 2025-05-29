Parse.Cloud.define("caseInsensitiveLogin", async (request) => {
  const { username, password } = request.params;

  if (!username || !password) {
    throw new Error("username and password are required.");
  }

  // Create individual queries for email and phone
  const userQuery = new Parse.Query(Parse.User);
  userQuery.matches("username", `^${username}$`, "i");

  try {
    // Find the user
    const user = await userQuery.first({ useMasterKey: true });

    if (!user) {
      throw new Parse.Error(404, "User does not exist");
    }

    // Check if the user is suspended
    if (user.get("isActive") === false) {
      throw new Parse.Error(
        403,
        "Your account is suspended. Please contact support."
      );
    }

    await Parse.User.logIn(username, password);

    // Get all roles the user is in
    const roleQuery = new Parse.Query(Parse.Role);
    roleQuery.equalTo("users", user);
    const roles = await roleQuery.find({ useMasterKey: true });

    const roleNames = roles.map((role) => role.get("name"));

    // Check if user has only "Player" role or no role
    if (
      roleNames.length === 0 ||
      (roleNames.length === 1 && roleNames[0] === "Player")
    ) {
      throw new Parse.Error(
        403,
        "Access denied. 'Player' role users cannot log in."
      );
    }

    return {
      success: true,
      user: {
        objectId: user.id,
        username: user.get("username"),
        email: user.get("email"),
        balance: user.get("balance"),
        roleName: roleNames[0],
      },
    };
  } catch (error) {
    throw new Error(`Login failed: ${error.message}`);
  }
});

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
