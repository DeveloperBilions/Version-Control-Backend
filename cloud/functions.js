const AWS = require("aws-sdk");

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

Parse.Cloud.define("createS3Folder", async (request) => {

  try {
    // Validate input
    const { folderName } = request.params;
    if (
      !folderName ||
      typeof folderName !== "string" ||
      folderName.trim() === ""
    ) {
      throw new Error("Missing or invalid 'folderName' parameter.");
    }

    // Validate environment variables
    const { AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, S3_BUCKET } =
      process.env;

    if (!AWS_ACCESS_KEY || !AWS_SECRET_KEY || !AWS_REGION || !S3_BUCKET) {
      throw new Error("One or more AWS environment variables are not set.");
    }

    const s3 = new AWS.S3({
      accessKeyId: AWS_ACCESS_KEY,
      secretAccessKey: AWS_SECRET_KEY,
      region: AWS_REGION,
    });

    const folderKey = `DevApplications/${folderName}/`;

    const params = {
      Bucket: S3_BUCKET,
      Key: folderKey,
      Body: "",
    };

    await s3.putObject(params).promise();

    return { success: true, code: 200, folderKey };
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
        message: `Failed to create S3 folder: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("uploadPDF", async (request) => {

  const { applicationId, version, fileName, fileBase64 } = request.params;

  // === Input validation ===
  if (!applicationId || !version || !fileName || !fileBase64) {
    throw new Parse.Error(
      400,
      "Missing required parameters: applicationId, version, fileName, fileBase64"
    );
  }

  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION,
  });

  const parentPrefix = `DevApplications/${applicationId}/`;
  const newVersionFolderKey = `DevApplications/${applicationId}/${version}/`;
  const fullFileKey = `${newVersionFolderKey}${fileName}`;

  try {
    // === Step 1: Check if parent folder exists ===
    const listResult = await s3
      .listObjectsV2({
        Bucket: process.env.S3_BUCKET,
        Prefix: parentPrefix,
        MaxKeys: 1,
      })
      .promise();

    if (!listResult.Contents || listResult.Contents?.length === 0) {
      throw new Parse.Error(
        404,
        `Parent folder ${parentPrefix} does not exist`
      );
    }

    // === Step 2: Create version folder marker ===
    await s3
      .putObject({
        Bucket: process.env.S3_BUCKET,
        Key: newVersionFolderKey,
        Body: "",
      })
      .promise();

    // === Step 3: Decode and upload PDF ===
    let buffer;
    try {
      buffer = Buffer.from(fileBase64, "base64");
    } catch {
      throw new Parse.Error(400, "Invalid base64 content");
    }

    await s3
      .putObject({
        Bucket: process.env.S3_BUCKET,
        Key: fullFileKey,
        Body: buffer,
        ContentType: "application/pdf",
      })
      .promise();

    return {
      success: true,
      message: `Folder and PDF uploaded`,
      folderKey: newVersionFolderKey,
      fileKey: fullFileKey,
      fileUrl: `https://s3.${process.env.AWS_REGION}.amazonaws.com/${process.env.S3_BUCKET}/${fullFileKey}`,
    };
  } catch (error) {
    console.error("UploadPDF Error:", error);
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

Parse.Cloud.define("editPDF", async (request) => {

  const { applicationId, version, fileName, fileBase64 } = request.params;

  // === Input validation ===
  if (!applicationId || !version || !fileName || !fileBase64) {
    throw new Parse.Error(
      400,
      "Missing required parameters: applicationId, version, fileName, fileBase64"
    );
  }

  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION,
  });

  const versionPrefix = `DevApplications/${applicationId}/${version}/`;
  const fullFileKey = `${versionPrefix}${fileName}`;

  try {
    // === Step 1: Check if version folder exists ===
    const listResult = await s3
      .listObjectsV2({
        Bucket: process.env.S3_BUCKET,
        Prefix: versionPrefix,
        MaxKeys: 1,
      })
      .promise();

    if (!listResult.Contents || listResult.Contents.length === 0) {
      throw new Parse.Error(
        404,
        `Version folder ${versionPrefix} does not exist`
      );
    }

    // === Step 2: Delete all files in the version folder ===
    const objectsToDelete = await s3
      .listObjectsV2({
        Bucket: process.env.S3_BUCKET,
        Prefix: versionPrefix,
      })
      .promise();

    // Filter out the "folder marker"
    const fileKeysOnly = objectsToDelete.Contents.filter(
      (obj) => obj.Key !== versionPrefix
    );

    if (fileKeysOnly.length > 0) {
      const deleteParams = {
        Bucket: process.env.S3_BUCKET,
        Delete: {
          Objects: fileKeysOnly.map((obj) => ({ Key: obj.Key })),
          Quiet: true,
        },
      };

      try {
        // Delete all files
        const deleteResult = await s3.deleteObjects(deleteParams).promise();
        console.log(`Deleted files in folder: ${versionPrefix}`);
        console.log(deleteResult);
      } catch (e) {
        console.error("Deletion failed", e);
      }
    }

    // === Step 3: Decode and upload PDF ===
    let buffer;
    try {
      buffer = Buffer.from(fileBase64, "base64");
    } catch {
      throw new Parse.Error(400, "Invalid base64 content");
    }

    await s3
      .putObject({
        Bucket: process.env.S3_BUCKET,
        Key: fullFileKey,
        Body: buffer,
        ContentType: "application/pdf",
      })
      .promise();

    return {
      success: true,
      message: `Folder and PDF uploaded`,
      folderKey: versionPrefix,
      fileKey: fullFileKey,
      fileUrl: `https://s3.${process.env.AWS_REGION}.amazonaws.com/${process.env.S3_BUCKET}/${fullFileKey}`,
    };
  } catch (error) {
    console.error("UploadPDF Error:", error);
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

Parse.Cloud.define("getSignedS3Url", async (request) => {

  const { fullUrl, disposition } = request.params;

  // === Validate input ===
  if (!fullUrl) {
    throw new Parse.Error(400, "Missing required parameter: fullUrl");
  }

  // === Remove the domain part to get the Key ===
  const prefix = `https://s3.${process.env.AWS_REGION}.amazonaws.com/${process.env.S3_BUCKET}/`;

  if (!fullUrl.startsWith(prefix)) {
    throw new Parse.Error(400, "Invalid S3 URL format");
  }

  // === Extract S3 Key ===
  const key = fullUrl.replace(prefix, "");
  if (!key) {
    throw new Parse.Error(400, "Unable to extract file key from URL");
  }

  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION,
  });

  const params = {
    Bucket: process.env.S3_BUCKET,
    Key: key,
    Expires: 60, // seconds
    ResponseContentDisposition:
      disposition === "attachment" ? "attachment" : "inline",
    ResponseContentType: "application/pdf",
  };

  try {
    const signedUrl = await s3.getSignedUrlPromise("getObject", params);
    return { success: true, code: 200, url: signedUrl };
  } catch (error) {
    console.error("Error generating signed URL:", error);
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

Parse.Cloud.define("createBuildConfig", async (request) => {
  const { 
    applicationId, 
    version, 
    WebGLVersion, 
    build_url, 
    forceUpdate, 
    manualUpdate, 
    manualUpdate_message 
  } = request.params;

  // === Input validation ===
  if (!applicationId || !version || !build_url) {
    throw new Parse.Error(
      400,
      "Missing required parameters: applicationId, version, build_url"
    );
  }

  try {
    // === Step 1: Ensure S3 folder exists using existing function ===
    const folderResult = await Parse.Cloud.run("createS3Folder", { folderName: applicationId });
    if (!folderResult.success) {
      throw new Parse.Error(500, `Failed to create S3 folder: ${folderResult.message}`);
    }

    // === Step 2: Setup S3 ===
    const s3 = new AWS.S3({
      accessKeyId: process.env.AWS_ACCESS_KEY,
      secretAccessKey: process.env.AWS_SECRET_KEY,
      region: process.env.AWS_REGION,
    });

    const buildConfigKey = `DevApplications/${applicationId}/build.json`;

    // === Step 3: Create build configuration object ===
    const buildConfig = {
      latest_build: {
        version: version,
        WebGLVersion: WebGLVersion || version,
        build_url: build_url,
        forceUpdate: forceUpdate || false,
        manualUpdate: manualUpdate || false,
        manualUpdate_message: manualUpdate_message || "",
        lastUpdated: new Date().toISOString()
      }
    };

    // === Step 4: Upload build.json to S3 ===
    await s3.putObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
      Body: JSON.stringify(buildConfig, null, 2),
      ContentType: "application/json",
    }).promise();

    return {
      success: true,
      message: "Build configuration created successfully",
      buildConfigKey: buildConfigKey,
      buildConfig: buildConfig
    };
  } catch (error) {
    console.error("CreateBuildConfig Error:", error);
    if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to create build configuration: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("updateBuildConfig", async (request) => {
  const { 
    applicationId, 
    version, 
    WebGLVersion, 
    build_url, 
    forceUpdate, 
    manualUpdate, 
    manualUpdate_message 
  } = request.params;

  // === Input validation ===
  if (!applicationId || !version || !build_url) {
    throw new Parse.Error(
      400,
      "Missing required parameters: applicationId, version, build_url"
    );
  }

  try {
    // === Step 1: Ensure S3 folder exists using existing function ===
    const folderResult = await Parse.Cloud.run("createS3Folder", { folderName: applicationId });
    if (!folderResult.success) {
      throw new Parse.Error(500, `Failed to create S3 folder: ${folderResult.message}`);
    }

    // === Step 2: Setup S3 ===
    const s3 = new AWS.S3({
      accessKeyId: process.env.AWS_ACCESS_KEY,
      secretAccessKey: process.env.AWS_SECRET_KEY,
      region: process.env.AWS_REGION,
    });

    const buildConfigKey = `DevApplications/${applicationId}/build.json`;

    // === Step 3: Try to get existing build config ===
    let existingConfig = {};
    try {
      const existingObject = await s3.getObject({
        Bucket: process.env.S3_BUCKET,
        Key: buildConfigKey,
      }).promise();
      existingConfig = JSON.parse(existingObject.Body.toString());
    } catch (getError) {
      // File doesn't exist, will create new one
      console.log("No existing build config found, creating new one");
    }

    // === Step 4: Update build configuration ===
    const updatedConfig = {
      ...existingConfig,
      latest_build: {
        version: version,
        WebGLVersion: WebGLVersion || version,
        build_url: build_url,
        forceUpdate: forceUpdate || false,
        manualUpdate: manualUpdate || false,
        manualUpdate_message: manualUpdate_message || "",
        lastUpdated: new Date().toISOString()
      }
    };

    // === Step 5: Upload updated build.json to S3 ===
    await s3.putObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
      Body: JSON.stringify(updatedConfig, null, 2),
      ContentType: "application/json",
    }).promise();

    return {
      success: true,
      message: "Build configuration updated successfully",
      buildConfigKey: buildConfigKey,
      buildConfig: updatedConfig
    };
  } catch (error) {
    console.error("UpdateBuildConfig Error:", error);
    if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to update build configuration: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("getBuildConfig", async (request) => {
  const { applicationId } = request.params;

  // === Input validation ===
  if (!applicationId) {
    throw new Parse.Error(400, "Missing required parameter: applicationId");
  }

  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION,
  });

  const buildConfigKey = `DevApplications/${applicationId}/build.json`;

  try {
    const result = await s3.getObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
    }).promise();

    const buildConfig = JSON.parse(result.Body.toString());

    return {
      success: true,
      buildConfig: buildConfig,
      buildConfigUrl: `https://s3.${process.env.AWS_REGION}.amazonaws.com/${process.env.S3_BUCKET}/${buildConfigKey}`
    };
  } catch (error) {
    console.error("GetBuildConfig Error:", error);
    if (error.code === 'NoSuchKey') {
      return {
        success: false,
        code: 404,
        message: "Build configuration not found for this application",
      };
    } else if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to get build configuration: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("listApplications", async (request) => {
  try {
    const Applications = Parse.Object.extend("Applications");
    const query = new Parse.Query(Applications);
    
    // Add filters to match existing data provider logic
    query.ascending("appName");
    query.notEqualTo("isDeleted", true);
    
    const results = await query.find({ useMasterKey: true });
    
    const applications = results.map(app => ({
      objectId: app.id,
      appName: app.get("appName"),
      packageId: app.get("packageId"),
      platform: app.get("platform"),
      createdAt: app.get("createdAt"),
      updatedAt: app.get("updatedAt")
    }));

    return {
      success: true,
      applications: applications
    };
  } catch (error) {
    console.error("ListApplications Error:", error);
    if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to list applications: ${error.message}`,
      };
    }
  }
});

// ============================================
// Root Build.json Management APIs
// ============================================

Parse.Cloud.define("getRootBuildConfig", async (request) => {
  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION,
  });

  const buildConfigKey = "build.json";

  try {
    const result = await s3.getObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
    }).promise();

    const buildConfig = JSON.parse(result.Body.toString());

    return {
      success: true,
      buildConfig: buildConfig,
      buildConfigUrl: `https://s3.${process.env.AWS_REGION}.amazonaws.com/${process.env.S3_BUCKET}/${buildConfigKey}`
    };
  } catch (error) {
    console.error("GetRootBuildConfig Error:", error);
    if (error.code === 'NoSuchKey') {
      return {
        success: false,
        code: 404,
        message: "Build configuration not found at root level",
      };
    } else if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to get root build configuration: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("createRootBuildConfig", async (request) => {
  const { 
    version, 
    WebGLVersion, 
    build_url, 
    forceUpdate, 
    manualUpdate, 
    manualUpdate_message 
  } = request.params;

  // === Input validation ===
  if (!version || !build_url) {
    throw new Parse.Error(
      400,
      "Missing required parameters: version, build_url"
    );
  }

  try {
    // === Setup S3 ===
    const s3 = new AWS.S3({
      accessKeyId: process.env.AWS_ACCESS_KEY,
      secretAccessKey: process.env.AWS_SECRET_KEY,
      region: process.env.AWS_REGION,
    });

    const buildConfigKey = "build.json";

    // === Check if build.json already exists ===
    try {
      await s3.headObject({
        Bucket: process.env.S3_BUCKET,
        Key: buildConfigKey,
      }).promise();
      
      // If we reach here, file exists
      return {
        success: false,
        code: 409,
        message: "Build configuration already exists at root level. Use update instead.",
      };
    } catch (headError) {
      // NoSuchKey means file doesn't exist, which is what we want
      if (headError.code !== 'NotFound' && headError.code !== 'NoSuchKey') {
        throw headError;
      }
    }

    // === Create build configuration object ===
    const buildConfig = {
      latest_build: {
        version: version,
        WebGLVersion: WebGLVersion || version,
        build_url: build_url,
        forceUpdate: forceUpdate || false,
        manualUpdate: manualUpdate || false,
        manualUpdate_message: manualUpdate_message || "",
        lastUpdated: new Date().toISOString()
      }
    };

    // === Upload build.json to S3 root ===
    await s3.putObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
      Body: JSON.stringify(buildConfig, null, 2),
      ContentType: "application/json",
    }).promise();

    return {
      success: true,
      message: "Root build configuration created successfully",
      buildConfigKey: buildConfigKey,
      buildConfig: buildConfig
    };
  } catch (error) {
    console.error("CreateRootBuildConfig Error:", error);
    if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to create root build configuration: ${error.message}`,
      };
    }
  }
});

Parse.Cloud.define("updateRootBuildConfig", async (request) => {
  const { 
    version, 
    WebGLVersion, 
    build_url, 
    forceUpdate, 
    manualUpdate, 
    manualUpdate_message 
  } = request.params;

  // === Input validation ===
  if (!version || !build_url) {
    throw new Parse.Error(
      400,
      "Missing required parameters: version, build_url"
    );
  }

  try {
    // === Setup S3 ===
    const s3 = new AWS.S3({
      accessKeyId: process.env.AWS_ACCESS_KEY,
      secretAccessKey: process.env.AWS_SECRET_KEY,
      region: process.env.AWS_REGION,
    });

    const buildConfigKey = "build.json";

    // === Try to get existing build config ===
    let existingConfig = {};
    try {
      const existingObject = await s3.getObject({
        Bucket: process.env.S3_BUCKET,
        Key: buildConfigKey,
      }).promise();
      existingConfig = JSON.parse(existingObject.Body.toString());
    } catch (getError) {
      // File doesn't exist, will create new one
      console.log("No existing root build config found, creating new one");
    }

    // === Update build configuration ===
    const updatedConfig = {
      ...existingConfig,
      latest_build: {
        version: version,
        WebGLVersion: WebGLVersion || version,
        build_url: build_url,
        forceUpdate: forceUpdate || false,
        manualUpdate: manualUpdate || false,
        manualUpdate_message: manualUpdate_message || "",
        lastUpdated: new Date().toISOString()
      }
    };

    // === Upload updated build.json to S3 root ===
    await s3.putObject({
      Bucket: process.env.S3_BUCKET,
      Key: buildConfigKey,
      Body: JSON.stringify(updatedConfig, null, 2),
      ContentType: "application/json",
    }).promise();

    return {
      success: true,
      message: "Root build configuration updated successfully",
      buildConfigKey: buildConfigKey,
      buildConfig: updatedConfig
    };
  } catch (error) {
    console.error("UpdateRootBuildConfig Error:", error);
    if (error instanceof Parse.Error) {
      return {
        success: false,
        code: error.code,
        message: error.message,
      };
    } else {
      return {
        success: false,
        code: 500,
        message: `Failed to update root build configuration: ${error.message}`,
      };
    }
  }
});