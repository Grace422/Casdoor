describe("Login test", () => {
  const selector = {
    username: "#input",
    password: "#normal_login_password",
    loginButton: ".ant-btn",
  };
  it("Login succeeded", () => {
    cy.request({
      method: "POST",
      url: "http://localhost:7001/api/login",
      body: {
        "application": "app-Nzhinusoft",
        "organization": "Nzhinusoft",
        "username": "grace",
        "password": "password",
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("ok");
    });
  });
  it("ui Login succeeded", () => {
    cy.visit("http://localhost:7001");
    cy.get(selector.username).type("grace");
    cy.get(selector.password).type("password");
    cy.get(selector.loginButton).click();
    cy.url().should("eq", "http://localhost:7001/");
  });

  it("Login failed", () => {
    cy.request({
      method: "POST",
      url: "http://localhost:7001/api/login",
      body: {
        "application": "app-Nzhinusoft",
        "organization": "Nzhinusoft",
        "username": "grace",
        "password": "1234",
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("error");
    });
  });
  it("ui Login failed", () => {
    cy.visit("http://localhost:7001");
    cy.get(selector.username).type("grace");
    cy.get(selector.password).type("1234");
    cy.get(selector.loginButton).click();
    cy.url().should("eq", "http://localhost:7001/login");
  });
});
