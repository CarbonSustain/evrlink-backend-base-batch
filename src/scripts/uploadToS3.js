const fs = require("fs");
const path = require("path");
const AWS = require("aws-sdk");

// Configure AWS SDK
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

const s3 = new AWS.S3();
const uploadsFolder = path.join(__dirname, "../uploads"); // Path to the uploads folder
const bucketName = process.env.S3_BUCKET_NAME;

// Function to upload a file to S3
const uploadFileToS3 = (filePath, fileName) => {
  const fileContent = fs.readFileSync(filePath);

  const params = {
    Bucket: bucketName,
    Key: `uploads/${fileName}`, // S3 key (path in the bucket)
    Body: fileContent,
    ACL: "public-read", // Make the file publicly readable
  };

  return s3.upload(params).promise();
};

// Main function to upload all files in the uploads folder
const uploadAllFiles = async () => {
  try {
    const files = fs.readdirSync(uploadsFolder);

    if (files.length === 0) {
      console.log("No files found in the uploads folder.");
      return;
    }

    for (const file of files) {
      const filePath = path.join(uploadsFolder, file);
      const stats = fs.statSync(filePath);

      if (stats.isFile()) {
        console.log(`Uploading ${file} to S3...`);
        const result = await uploadFileToS3(filePath, file);
        console.log(`Uploaded ${file} successfully: ${result.Location}`);
      }
    }

    console.log("All files have been uploaded to S3.");
  } catch (error) {
    console.error("Error uploading files to S3:", error);
  }
};

// Run the script
uploadAllFiles();
