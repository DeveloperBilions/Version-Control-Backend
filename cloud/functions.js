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

    const loggedInUser = await Parse.User.logIn(username, password);

    // Get all roles the user is in
    const roleQuery = new Parse.Query(Parse.Role);
    roleQuery.equalTo("users", user);
    const roles = await roleQuery.find({ useMasterKey: true });

    const roleNames = roles.map((role) => role.get("name"));

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

Parse.Cloud.define("createUser", async (request) => {
  const { username, email, password, confirmpassword, role, manager } =
    request.params;

  if (
    !username ||
    !email ||
    !password ||
    !confirmpassword ||
    !role ||
    !manager
  ) {
    throw new Error("Missing required parameters.");
  }

  if (password !== confirmpassword) {
    throw new Error("Passwords do not match.");
  }

  try {
    // 🔍 Step 1: Fetch manager user
    const managerQuery = new Parse.Query(Parse.User);
    managerQuery.equalTo("objectId", manager);
    const managerUser = await managerQuery.first({ useMasterKey: true });

    if (!managerUser) {
      throw new Error("Manager not found.");
    }

    const managerACL = managerUser.getACL();

    // 🧱 Step 2: Role pointer
    const Role = Parse.Object.extend("_Role");
    const rolePointer = new Role();
    rolePointer.id = role;

    // 👤 Step 3: Create user
    const user = new Parse.User();
    user.set("username", username);
    user.set("email", email);
    user.set("publicEmail", email);
    user.set("password", password);
    user.set("role", rolePointer);
    user.set("manager", managerUser);

    // 🚀 Step 4: Sign up user
    const newUser = await user.signUp(null);

    // 🔐 Step 5: Copy manager ACL + add user ACL
    const newACL = new Parse.ACL();

    if (managerACL && managerACL.permissionsById) {
      const ids = Object.keys(managerACL.permissionsById);
      for (const id of ids) {
        const perms = managerACL.permissionsById[id];
        if (perms.read) newACL.setReadAccess(id, true);
        if (perms.write) newACL.setWriteAccess(id, true);
      }
    }

    newACL.setReadAccess(newUser.id, true);
    newACL.setWriteAccess(newUser.id, true);

    newUser.setACL(newACL);
    await newUser.save(null, { useMasterKey: true });

    // 🎭 Step 6: Add user to Role's users relation
    const roleQuery = new Parse.Query(Parse.Role);
    roleQuery.equalTo("objectId", role);
    const roleObj = await roleQuery.first({ useMasterKey: true });

    if (!roleObj) {
      throw new Error("Role not found.");
    }

    roleObj.relation("users").add(newUser);
    await roleObj.save(null, { useMasterKey: true });

    return { success: true, user: newUser };

    return { success: true, user: newUser };
  } catch (error) {
    throw new Error(`User Creation failed: ${error.message}`);
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
