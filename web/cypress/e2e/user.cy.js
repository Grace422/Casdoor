describe('Test User', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test user", () => {
        cy.visit("http://localhost:7001");
        cy.visit("http://localhost:7001/users");
        cy.url().should("eq", "http://localhost:7001/users");
        cy.visit("http://localhost:7001/users/Nzhinusoft/grace");
        cy.url().should("eq", "http://localhost:7001/users/Nzhinusoft/grace");
    });
})
