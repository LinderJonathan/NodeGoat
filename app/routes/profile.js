const ProfileDAO = require("../data/profile-dao").ProfileDAO;
const ESAPI = require("node-esapi");
const sanitizeHtml = require("sanitize-html");
const {
    environmentalScripts
} = require("../../config/config");

/* The ProfileHandler must be constructed with a connected db */
function ProfileHandler(db) {
    "use strict";

    const profile = new ProfileDAO(db);

    this.displayProfile = (req, res, next) => {
        const {
            userId
        } = req.session;



        profile.getByUserId(parseInt(userId), (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;

            doc.website = ESAPI.encoder().encodeForHTML(doc.website); // already in place by NodeGoat contributor
            /*
            Mitigative XSS layer: encoding upon load of the page. Apart from OWASP's encoding of HTML
            also encode for URL and JavaScript contexts.
            */
            doc.website = ESAPI.encoder().encodeForJavaScript(doc.website);
            doc.website = ESAPI.encoder().encodeForURL(doc.website);

            return res.render("profile", {
                ...doc,
                environmentalScripts
            });
        });
    };

    this.handleProfileUpdate = (req, res, next) => {

        const {
            firstName,
            lastName,
            ssn,
            dob,
            address,
            bankAcc,
            bankRouting
        } = req.body;
        // Fix for Section: ReDoS attack
        // The following regexPattern that is used to validate the bankRouting number is insecure and vulnerable to
        // catastrophic backtracking which means that specific type of input may cause it to consume all CPU resources
        // with an exponential time until it completes
        // --
        // The Fix: Instead of using greedy quantifiers the same regex will work if we omit the second quantifier +
        // const regexPattern = /([0-9]+)\#/;


        /*
        Mitigative XSS layer: Validating user input with Regular Expressions on submitting/updating the profile

        By validating each input for each field according to regex patterns, bypassing with malicious attacks becomes
        difficult. Here, NodeGoat already provided the regex pattern for 'bankRouting'
        */
        // Allow only numbers with a suffix of the letter #, for example: 'XXXXXX#' (by OWASP)
        const regexPattern = /([0-9]+)+\#/; // already in place by NodeGoat contributor
        const testComplyWithRequirements = regexPattern.test(bankRouting);      

        // Allow only upper/lower alphabetical chars
        const regexTextField = /^[a-zA-Z\s-]+$/;
        const testFirstName = regexTextField.test(firstName);
        const testLastName = regexTextField.test(lastName);
        

        function profileRender(errorResponse) {
            const firstNameSafeString = firstName;
            return res.render("profile", {
                updateError: errorResponse,
                firstNameSafeString,
                lastName,
                ssn,
                dob,
                address,
                bankAcc,
                bankRouting,
                environmentalScripts
            });
        }

        /*
        Checks if user input violates the format
        If it does, it calls for 'profileRender' which in turn sends an error message and
        won't update the fields
        */
        if (testFirstName !== true) {
            profileRender("Sorry, first names only contain lower/upper case letters and binders/apostrophes");
        }
        if (testLastName !== true) {
            profileRender("Sorry, last names contain lower/upper case letters and binders/apostrophes");       
        }
        if (testComplyWithRequirements !== true) {
            profileRender("Bank Routing number does not comply with requirements for format specified");
        }

        const {
            userId
        } = req.session;
        
        /*
        Mitigative XSS layer: Encode all user inputs with npm "sanitize-html"
        Link: https://www.npmjs.com/package/sanitize-html
        
        This is yet another sanitization layer that works to prevent a user from inputing malicious payload into
        input fields on the profile page. While this sanitization defaults to blocking
        all HTML, it can be specified which tags or attributes should be allowed. For instance, a <b>bold</b> is mostly
        harmless, and is sometimes part of functionality. By creating a whitelist on tags and attributes, 
        they can bypass sanitization

        Incredibly important that we sanitize BEFORE we update the user's profile
        */


        const firstNameSanitized = sanitizeHtml(firstName);
        const lastNameSanitized = sanitizeHtml(lastName);
        const ssnSanitized = sanitizeHtml(ssn);
        const dobSanitized = sanitizeHtml(dob);
        const addressSanitized= sanitizeHtml(address);
        const bankAccSanitized = sanitizeHtml(bankAcc);
        const bankRoutingSanitized= sanitizeHtml(bankRouting);

        profile.updateUser(
            parseInt(userId),
            firstNameSanitized,
            lastNameSanitized,
            ssnSanitized,
            dobSanitized,
            addressSanitized,
            bankAccSanitized,
            bankRoutingSanitized,
            (err, user) => {

                if (err) return next(err);

                // WARN: Applying any sting specific methods here w/o checking type of inputs could lead to DoS by HPP
                //firstName = firstName.trim();
                user.updateSuccess = true;
                user.userId = userId;

                return res.render("profile", {
                    ...user,
                    environmentalScripts
                });
            }
        );

    };

}

module.exports = ProfileHandler;
