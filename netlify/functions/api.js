const serverless = require("serverless-http");
const { app, initializeDatabase } = require("../../server");

exports.handler = async (event, context) => {
  try {
    await initializeDatabase();

    const handler = serverless(app);

    return await handler(event, context);
  } catch (error) {
    console.error("Netlify Function Error:", error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Server gagal memproses permintaan."
      })
    };
  }
};