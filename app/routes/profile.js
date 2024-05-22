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

            // @TODO @FIXME
            // while the developer intentions were correct in encoding the user supplied input so it
            // doesn't end up as an XSS attack, the context is incorrect as it is encoding the firstname for HTML
            // while this same variable is also used in the context of a URL link element

            /*
            VULNERABLE POINTS: URL context not encoded
            */
            doc.website = ESAPI.encoder().encodeForHTML(doc.website);
            doc.website = ESAPI.encoder().encodeForJavaScript(doc.website);

            /*
            Mitigative XSS layer: also encode for URL contexts
            See below for encoding
            */
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
        const stringFields = [firstName, lastName, ssn]
        // Fix for Section: ReDoS attack
        // The following regexPattern that is used to validate the bankRouting number is insecure and vulnerable to
        // catastrophic backtracking which means that specific type of input may cause it to consume all CPU resources
        // with an exponential time until it completes
        // --
        // The Fix: Instead of using greedy quantifiers the same regex will work if we omit the second quantifier +
        // const regexPattern = /([0-9]+)\#/;

        // Allow only numbers with a suffix of the letter #, for example: 'XXXXXX#'
        const regexPattern = /([0-9]+)+\#/;
        const testComplyWithRequirements = regexPattern.test(bankRouting);

        // strictly allows upper/lower alphabetical chars and '-', ' ' '
        /*
        Mitigative XSS layer: Validating user input with Regular Expressions

        By validating each input for each field according to regex patterns, bypassing with malicious attacks becomes
        difficult. Here, NodeGoat already provided the regex pattern for 
        */
        const regexTextField = /^[a-zA-Z\s-]+$/;
        const testFirstName = regexTextField.test(lastName);
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
        if (testFirstName !== true) {
            profileRender("Sorry, first names only contain lower/upper case letters and binders/apostrophes");
        }
        else if (testLastName !== true) {
            profileRender("Sorry, last names contain lower/upper case letters and binders/apostrophes");       
        }
        else if (testComplyWithRequirements !== true) {
            profileRender("Bank Routing number does not comply with requirements for format specified");
        }

        const {
            userId
        } = req.session;
        
        /*
        Mitigative XSS layer: Encode all user inputs
        
        This sanitization works to prevent stored XSS. While this sanitization defaults to blocking
        all HTML, it can be specified which tags or attributes should be allowed. For instance, a <b>bold</b> is mostly
        harmless, and is sometimes part of functionality. By creating a whitelist on tags and attributes, 
        they can bypass sanitization
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
