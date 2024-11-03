import React, { useState } from "react";
import axios from "axios";
import "./Login.scss";

const SignInForm = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [token, setToken] = useState("");
  const [copySuccess, setCopySuccess] = useState(false);
  const [loginStatus, setLoginStatus] = useState({success: false, message: ""});

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://localhost:3001/login", {
        username,
        password,
      });
      setMessage(`Success Login!`);
      setToken(response.data.accessToken);
      setLoginStatus({success: true, message: "Login Successful. Welcome!"});
      console.log("Login successful: here's your JSON Web Token ->", response.data);
    } catch (error) {
      setLoginStatus({success: false, message: "Login Failed. Please check your credentials."});
      setMessage(`Login Failed. Please check your credentials.`);
      setToken("");
      console.error("Error logging in:", error);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopySuccess(true);
      } catch (error) {
        console.error("Failed to copy: ", error);
    }
  }

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
      {loginStatus.message && (
        <div className={`Login__message ${loginStatus.success ? 'Login__message--success' : 'Login__message--error'}`}>
          {loginStatus.message}
        </div>
      )}
      <div className="Login__tokenWrapper">
        <div className="Login__tokenContainer">
          <p className="Login__token">{token}</p>
          {token && (
            <button
              onClick={handleCopy}
              className={`Login__copyButton ${copySuccess ? 'Login__copyButton--success' : ''}`}
            >
              {copySuccess ? "Copied!" : "Copy Token"}
            </button>
          )}
        </div>
       </div>
    </div>
  );
};

export default SignInForm;
