import React, { useState } from "react";
import axios from "axios";
import "./Login.scss";

const SignInForm = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post("http://localhost:3001/login", {
        username,
        password,
      });
      setMessage(`Success! Jwt token => ${response.data.accessToken}`);

      console.log("Login successful: here's the jwt token ->", response.data);
    } catch (error) {
      setMessage("Login failed. Please check your credentials.");
      console.error("Error logging in:", error);
    }
  };

  fetch("http://localhost:3001/login", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username: username,
      password: password,
    }),
  });

  return (
    <div className="Login">
      <h2 className="Login__title">Sign In</h2>
      <form onSubmit={handleSubmit} className="Login__form">
        <div className="Login__instructions">
          Please enter following username and password to emulate
          your login experience
          <br />
          <br />
          username: admin
          <br />
          password: password
        </div>
        <br />
        <div className="Login__username">
          <label className="Login__labelUserName">Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="Login__inputUserName"
          />
        </div>
        <div className="Login__password">
          <label className="Login__labelPassword">Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="Login__inputPassword"
          />
        </div>
        <button type="submit" className="Login__button">Sign In</button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
};

export default SignInForm;
