require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const admin = require('firebase-admin')
const port = process.env.PORT || 3000
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString(
  'utf-8'
)
const serviceAccount = JSON.parse(decoded)
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
})

const app = express()
// middleware
app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      'https://b12-m11-session.web.app',
      'https://assignment-11-auth-a379f.web.app'
    ],
    credentials: true,
    optionSuccessStatus: 200,
  })
)
app.use(express.json())

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(' ')[1]
  console.log(token)
  if (!token) return res.status(401).send({ message: 'Unauthorized Access!' })
  try {
    const decoded = await admin.auth().verifyIdToken(token)
    req.tokenEmail = decoded.email
    console.log(decoded)
    next()
  } catch (err) {
    console.log(err)
    return res.status(401).send({ message: 'Unauthorized Access!', err })
  }
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})
async function run() {
  try {
    // db collections
    const db = client.db('loanLinkDB');
    const loansCollection = db.collection('all-Loans');
    const applicationCollection = db.collection('loan-application');
    const usersCollection = db.collection('users');

    // role middlewares
    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (user?.role !== 'admin')
        return res
          .status(403)
          .send({ message: 'Admin only Actions!', role: user?.role })

      next()
    }

    const verifyMANAGER = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (user?.role !== 'manager')
        return res
          .status(403)
          .send({ message: 'Manager only Actions!', role: user?.role })

      next()
    }

    // loans related apis
    // all loans
    app.get('/all-loans', async (req, res) => {
      const email = req.query.email;
      const query = {};
      if (email) {
        query.createdBy = email;
      }
      const result = await loansCollection.find(query).toArray();
      res.send(result)
    })

    // all loans for search sort pagination
    app.get('/explore-loans', async (req, res) => {
      const {
        category,
        limit = 0,
        skip = 0,
        sort = 'interestRate',
        order = 'asc',
        search = ''
      } = req.query;

      const filter = {};
      if (category) {
        filter.category = category;
      }
      if (search) {
        filter.title = { $regex: search, $options: 'i' };
      }

      const sortOption = {};
      sortOption[sort] = order === "asc" ? 1 : -1;

      const cursor = loansCollection
        .find(filter)
        .sort(sortOption)
        .limit(Number(limit))
        .skip(Number(skip));

      const loans = await cursor.toArray();

      // If you want count of filtered docs, use same filter
      const count = await loansCollection.countDocuments(filter);

      res.send({ loans, total: count });
    });

    // get a loan details
    app.get('/loan/:id', async (req, res) => {
      const id = req.params.id;
      const result = await loansCollection.findOne({ _id: new ObjectId(id) });
      res.send(result)
    })

    app.post('/add-loan', verifyJWT, verifyMANAGER, async (req, res) => {
      const loanData = req.body;
      loanData.createdAt = new Date();
      const result = await loansCollection.insertOne(loanData);
      res.send(result);
    })

    app.patch('/update-loan/:id', verifyJWT, async (req, res) => {
      const updateData = req.body;
      updateData.updatedAt = new Date();
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: updateData
      };
      const result = await loansCollection.updateOne(query, update);
      res.send(result);
    });

    app.delete('/delete-loan/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await loansCollection.deleteOne(query);
      res.send(result)
    })




    // application related apis
    app.get('/applications', verifyJWT, async (req, res) => {
      const email = req.query.email;
      const updatedBy = req.query.updatedBy;
      const status = req.query.status;
      const query = {};
      if (email) {
        query.borrowerEmail = email;
      }
      if (updatedBy) {
        query.updatedBy = updatedBy;
      }
      if (status) {
        query.status = status;
      }
      const result = await applicationCollection.find(query).toArray();
      res.send(result);
    })

    app.get('/application-details/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const result = await applicationCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    })

    app.post('/applications', verifyJWT, async (req, res) => {
      const application = req.body;
      application.appliedAt = new Date();
      const result = await applicationCollection.insertOne(application);
      res.send(result);
    })

    app.patch('/applications/:id', verifyJWT, async (req, res) => {
      const updateData = req.body;
      updateData.updatedAt = new Date();
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: updateData
      };
      const result = await applicationCollection.updateOne(query, update);
      res.send(result);
    })

    app.delete('/my-applications/:id', verifyJWT, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await applicationCollection.deleteOne(query);
      res.send(result)
    })


    // save or update a user in db
    // get all users
    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result)
    })

    app.post('/users', async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      userData.role = 'borrower'

      const query = {
        email: userData.email
      }

      const alreadyExists = await usersCollection.findOne(query);
      if (alreadyExists) {
        const result = await usersCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString()
          }
        })
        return res.send(result)
      }

      const result = await usersCollection.insertOne(userData);
      res.send(result)
    })

    // get a users role
    app.get('/user/role', verifyJWT, async (req, res) => {
      try {
        const queryEmail = req.query.email;
        const tokenEmail = req.tokenEmail;

        // email spoofing protection
        if (!queryEmail || queryEmail !== tokenEmail) {
          return res.status(403).send({ role: null });
        }

        const user = await usersCollection.findOne({ email: tokenEmail });

        if (!user) {
          return res.status(404).send({ role: null });
        }

        res.send({ role: user.role });
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user role' });
      }
    });

    // update user role
    app.patch('/user/:id', verifyJWT, verifyADMIN, async (req, res) => {
      const updateData = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const update = {
        $set: updateData
      };
      const result = await usersCollection.updateOne(query, update);
      res.send(result);
    })

    // loan card apis for home screen
    app.get('/loan-cards-display', async (req, res) => {
      const query = { showOnHome: true };
      const result = await loansCollection
        .find(query)
        .sort({ updatedAt: -1 })
        .limit(8)
        .toArray();
      res.send(result);
    })




    // payment related apis
    app.post('/create-checkout-session', async (req, res) => {
      try {
        const paymentInfo = req.body;

        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: 'USD',
                unit_amount: 1000,
                product_data: {
                  name: paymentInfo.loanTitle,
                },
              },
              quantity: 1,
            },
          ],
          customer_email: paymentInfo.borrowerEmail,
          mode: 'payment',
          metadata: {
            applicationID: paymentInfo.applicationID,
            loanID: paymentInfo.loanID,
          },
          success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
        });

        res.send({ url: session.url });
        console.log(session);
      } catch (error) {
        console.error("Stripe Checkout Error:", error);
        res.status(500).send({ message: "Stripe session creation failed", error });
      }
    });


    app.patch('/payment-success', async (req, res) => {
      try {
        const sessionId = req.query.session_id;

        if (!sessionId) {
          return res.status(400).send({ success: false, message: "Missing session_id" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === 'paid') {
          const id = session.metadata.applicationID;
          const transactionId = session.payment_intent;

          const query = { _id: new ObjectId(id) };
          const update = {
            $set: {
              applicationFee: 'paid',
              feePaidAt: new Date(),
              transactionId
            }
          };

          const result = await applicationCollection.updateOne(query, update);

          return res.send({
            success: true,
            transactionId: session.payment_intent,
            modifyParcel: result,
          });
        }

        return res.send({ success: false, message: "Payment not completed" });

      } catch (error) {
        console.error("Payment success patch error:", error);
        res.status(500).send({ success: false, error: error.message });
      }
    });



    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    // console.log('Pinged your deployment. You successfully connected to MongoDB!')

  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir)

app.get('/', (req, res) => {
  res.send('Hello from Server..')
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
