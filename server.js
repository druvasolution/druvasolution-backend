const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET || 'dev-only-change-this-secret';

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || '';

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || '';

const DATA_FILE =
    path.join(__dirname, 'data', 'customers.json');


/* Create data folder automatically */

fs.mkdirSync(path.dirname(DATA_FILE), {
    recursive: true
});


app.use(cors());

app.use(express.json());


/* =========================================================
   CUSTOMER DATA FUNCTIONS
========================================================= */

function readCustomers() {

    try {

        return JSON.parse(
            fs.readFileSync(DATA_FILE, 'utf8')
        );

    } catch {

        return [];

    }

}


function writeCustomers(customers) {

    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(customers, null, 2)
    );

}


function publicCustomer(customer) {

    const {
        passwordHash,
        ...safe
    } = customer;

    return safe;

}


/* =========================================================
   LICENSE KEY
========================================================= */

function generateLicenseKey() {

    return 'DS-' +
        crypto
            .randomBytes(5)
            .toString('hex')
            .toUpperCase();

}


/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', (req, res) => {

    res.json({
        ok: true,
        service: 'DruvaSolution API'
    });

});


/* =========================================================
   TEMPORARY CUSTOMER SETUP
   Used only for initial testing
========================================================= */

app.post('/api/setup/customer', async (req, res) => {

    try {

        const {
            name,
            email,
            username,
            password
        } = req.body;


        if (
            !name ||
            !email ||
            !username ||
            !password
        ) {

            return res.status(400).json({
                message:
                    'name, email, username and password are required.'
            });

        }


        if (password.length < 6) {

            return res.status(400).json({
                message:
                    'Password must be at least 6 characters.'
            });

        }


        const customers = readCustomers();


        const exists = customers.some(c =>

            c.email.toLowerCase() ===
            email.toLowerCase()

            ||

            c.username.toLowerCase() ===
            username.toLowerCase()

        );


        if (exists) {

            return res.status(409).json({
                message:
                    'Email or username already exists.'
            });

        }


        const customer = {

            id: Date.now().toString(),

            name,

            email,

            username,

            passwordHash:
                await bcrypt.hash(password, 12),

            active: true,

            software:
                'Courier Billing Software',

            licenseKey:
                generateLicenseKey(),

            expiryDate:
                '2027-12-31',

            createdAt:
                new Date().toISOString()

        };


        customers.push(customer);

        writeCustomers(customers);


        res.status(201).json({

            customer:
                publicCustomer(customer)

        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                'Unable to create customer.'
        });

    }

});


/* =========================================================
   CUSTOMER LOGIN
========================================================= */

app.post('/api/login', async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;


        if (!username || !password) {

            return res.status(400).json({
                message:
                    'Username/email and password are required.'
            });

        }


        const customers = readCustomers();


        const customer =
            customers.find(c =>

                c.email.toLowerCase() ===
                username.toLowerCase()

                ||

                c.username.toLowerCase() ===
                username.toLowerCase()

            );


        if (
            !customer ||
            !customer.active ||
            !(await bcrypt.compare(
                password,
                customer.passwordHash
            ))
        ) {

            return res.status(401).json({
                message:
                    'Invalid username/email or password.'
            });

        }


        const token = jwt.sign(

            {
                customerId:
                    customer.id,

                role:
                    'customer'

            },

            JWT_SECRET,

            {
                expiresIn:
                    '8h'
            }

        );


        res.json({

            token,

            customer:
                publicCustomer(customer)

        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                'Login failed.'
        });

    }

});


/* =========================================================
   CUSTOMER AUTH
========================================================= */

function auth(req, res, next) {

    const header =
        req.headers.authorization || '';

    const token =
        header.startsWith('Bearer ')
            ? header.slice(7)
            : '';


    if (!token) {

        return res.status(401).json({
            message:
                'Login required.'
        });

    }


    try {

        req.user =
            jwt.verify(
                token,
                JWT_SECRET
            );


        next();


    } catch {

        res.status(401).json({
            message:
                'Session expired. Please login again.'
        });

    }

}


/* =========================================================
   CUSTOMER PROFILE
========================================================= */

app.get('/api/me', auth, (req, res) => {

    const customer =
        readCustomers().find(
            c =>
                c.id ===
                req.user.customerId
        );


    if (
        !customer ||
        !customer.active
    ) {

        return res.status(404).json({
            message:
                'Customer not found.'
        });

    }


    res.json({

        customer:
            publicCustomer(customer)

    });

});


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post('/api/admin/login', (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;


        if (
            !ADMIN_USERNAME ||
            !ADMIN_PASSWORD
        ) {

            return res.status(503).json({
                message:
                    'Admin credentials are not configured on the server.'
            });

        }


        if (
            username !== ADMIN_USERNAME ||
            password !== ADMIN_PASSWORD
        ) {

            return res.status(401).json({
                message:
                    'Invalid admin username or password.'
            });

        }


        const token = jwt.sign(

            {
                role:
                    'admin',

                username:
                    ADMIN_USERNAME

            },

            JWT_SECRET,

            {
                expiresIn:
                    '8h'
            }

        );


        res.json({

            token,

            admin: {

                username:
                    ADMIN_USERNAME,

                role:
                    'admin'

            }

        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                'Admin login failed.'
        });

    }

});


/* =========================================================
   ADMIN AUTH
========================================================= */

function adminAuth(req, res, next) {

    const header =
        req.headers.authorization || '';

    const token =
        header.startsWith('Bearer ')
            ? header.slice(7)
            : '';


    if (!token) {

        return res.status(401).json({
            message:
                'Admin login required.'
        });

    }


    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );


        if (
            decoded.role !==
            'admin'
        ) {

            return res.status(403).json({
                message:
                    'Admin access required.'
            });

        }


        req.admin =
            decoded;


        next();


    } catch {

        return res.status(401).json({
            message:
                'Admin session expired.'
        });

    }

}


/* =========================================================
   ADMIN - CUSTOMER LIST
========================================================= */

app.get(
    '/api/admin/customers',
    adminAuth,
    (req, res) => {

        const customers =
            readCustomers()
                .map(publicCustomer);


        res.json({
            customers
        });

    }
);


/* =========================================================
   ADMIN - SINGLE CUSTOMER
========================================================= */

app.get(
    '/api/admin/customers/:id',
    adminAuth,
    (req, res) => {

        const customer =
            readCustomers().find(
                c =>
                    c.id ===
                    req.params.id
            );


        if (!customer) {

            return res.status(404).json({
                message:
                    'Customer not found.'
            });

        }


        res.json({

            customer:
                publicCustomer(customer)

        });

    }
);


/* =========================================================
   ADMIN - ADD CUSTOMER
========================================================= */

app.post(
    '/api/admin/customers',
    adminAuth,
    async (req, res) => {

        try {

            const {

                name,
                email,
                username,
                password,
                software,
                licenseKey,
                expiryDate,
                active

            } = req.body;


            if (
                !name ||
                !email ||
                !username ||
                !password
            ) {

                return res.status(400).json({
                    message:
                        'Name, email, username and password are required.'
                });

            }


            if (password.length < 6) {

                return res.status(400).json({
                    message:
                        'Password must be at least 6 characters.'
                });

            }


            const customers =
                readCustomers();


            const exists =
                customers.some(c =>

                    c.email.toLowerCase() ===
                    email.toLowerCase()

                    ||

                    c.username.toLowerCase() ===
                    username.toLowerCase()

                );


            if (exists) {

                return res.status(409).json({
                    message:
                        'Email or username already exists.'
                });

            }


            const customer = {

                id:
                    Date.now().toString(),

                name,

                email,

                username,

                passwordHash:
                    await bcrypt.hash(
                        password,
                        12
                    ),

                active:
                    active !== false,

                software:
                    software ||
                    'Courier Billing Software',

                licenseKey:
                    licenseKey ||
                    generateLicenseKey(),

                expiryDate:
                    expiryDate ||
                    '2027-12-31',

                createdAt:
                    new Date().toISOString()

            };


            customers.push(customer);

            writeCustomers(customers);


            res.status(201).json({

                message:
                    'Customer created successfully.',

                customer:
                    publicCustomer(customer)

            });


        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to create customer.'
            });

        }

    }
);


/* =========================================================
   ADMIN - UPDATE CUSTOMER
========================================================= */

app.put(
    '/api/admin/customers/:id',
    adminAuth,
    async (req, res) => {

        try {

            const customers =
                readCustomers();


            const index =
                customers.findIndex(
                    c =>
                        c.id ===
                        req.params.id
                );


            if (index === -1) {

                return res.status(404).json({
                    message:
                        'Customer not found.'
                });

            }


            const customer =
                customers[index];


            const {

                name,
                email,
                username,
                password,
                software,
                licenseKey,
                expiryDate,
                active

            } = req.body;


            if (email) {

                const emailExists =
                    customers.some(
                        (c, i) =>
                            i !== index &&
                            c.email.toLowerCase() ===
                            email.toLowerCase()
                    );


                if (emailExists) {

                    return res.status(409).json({
                        message:
                            'Email already exists.'
                    });

                }

            }


            if (username) {

                const usernameExists =
                    customers.some(
                        (c, i) =>
                            i !== index &&
                            c.username.toLowerCase() ===
                            username.toLowerCase()
                    );


                if (usernameExists) {

                    return res.status(409).json({
                        message:
                            'Username already exists.'
                    });

                }

            }


            if (name !== undefined)
                customer.name = name;


            if (email !== undefined)
                customer.email = email;


            if (username !== undefined)
                customer.username = username;


            if (software !== undefined)
                customer.software = software;


            if (licenseKey !== undefined)
                customer.licenseKey = licenseKey;


            if (expiryDate !== undefined)
                customer.expiryDate = expiryDate;


            if (active !== undefined)
                customer.active = active;


            if (password) {

                if (password.length < 6) {

                    return res.status(400).json({
                        message:
                            'Password must be at least 6 characters.'
                    });

                }


                customer.passwordHash =
                    await bcrypt.hash(
                        password,
                        12
                    );

            }


            customer.updatedAt =
                new Date().toISOString();


            customers[index] =
                customer;


            writeCustomers(customers);


            res.json({

                message:
                    'Customer updated successfully.',

                customer:
                    publicCustomer(customer)

            });


        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to update customer.'
            });

        }

    }
);


/* =========================================================
   ADMIN - DELETE CUSTOMER
========================================================= */

app.delete(
    '/api/admin/customers/:id',
    adminAuth,
    (req, res) => {

        try {

            const customers =
                readCustomers();


            const index =
                customers.findIndex(
                    c =>
                        c.id ===
                        req.params.id
                );


            if (index === -1) {

                return res.status(404).json({
                    message:
                        'Customer not found.'
                });

            }


            customers.splice(
                index,
                1
            );


            writeCustomers(customers);


            res.json({

                message:
                    'Customer deleted successfully.'

            });


        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    'Unable to delete customer.'
            });

        }

    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            `DruvaSolution API running on port ${PORT}`
        );

    }
);
