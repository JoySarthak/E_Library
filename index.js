const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const bcrypt = require("bcrypt");
const app = express();
const jwt = require("jsonwebtoken"); // Added JWT for session handling
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const SECRET_KEY = "mHn3Q8zYtnv5Gv4jR1XJp2zS6oWxF97b";
// MongoDB Connection
mongoose
  .connect("mongodb://localhost:27017/Users")
  .then(() => {
    console.log("✅ Database Connected Successfully");
  })
  .catch((error) => {
    console.error("❌ Connection error:", error);
  });

// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  status: { type: String, enum: ["Active", "Inactive"], default: "Active" },
  borrowedBooks: [
    {
      bookId: { type: mongoose.Schema.Types.ObjectId, ref: "Book" }, // Reference to Book model
      dueDate: { type: Date, required: true },
      status: { type: String, enum: ["Active", "Expired"], default: "Active" },
    },
  ],
});

const User = mongoose.model("Student", userSchema);

const adminSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
});

const Admin = mongoose.model("Admins", adminSchema);

const bookSchema = new mongoose.Schema({
  title: String,
  author: String,
  copies: Number,
  availableCopies: Number,
  isbn: String,
});

const Book = mongoose.model("Book", bookSchema);

const requestSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: "Student" },
  book: { type: mongoose.Schema.Types.ObjectId, ref: "Book" },
  requestDate: { type: Date, default: Date.now },
  dueDate: Date,
  status: {
    type: String,
    enum: ["Pending", "Approved", "Rejected"],
    default: "Pending",
  },
  fine: { type: Number, default: 0 },
});

const Request = mongoose.model("Request", requestSchema);

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

app.get("/student", (req, res) => {
  res.sendFile(path.join(__dirname, "student.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Authentication Routes
app.post("/post", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User already exists with this username or email" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

app.post("/logon", async (req, res) => {
  try {
    const { role, username, password } = req.body;
    let user;

    console.log("Login attempt:", { role, username });

    if (role === "admin") {
      user = await Admin.findOne({ username });
      if (!user) {
        console.log("Admin not found");
        return res.status(404).json({ error: "Admin not found" });
      }
    } else if (role === "student") {
      user = await User.findOne({ username });
      if (!user) {
        console.log("Student not found");
        return res.status(404).json({ error: "Student not found" });
      }
    } else {
      console.log("Invalid role selected");
      return res.status(400).json({ error: "Invalid role selected" });
    }

    let passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      console.log("Incorrect password");
      return res.status(401).json({ error: "Incorrect password" });
    }

    // Generate JWT token
    const token = jwt.sign({ username: user.username, role }, SECRET_KEY, {
      expiresIn: "1h",
    });

    console.log("Login successful for:", username);

    // Store token in cookie (optional)
    res.cookie("token", token, { httpOnly: true });

    // Send success response
    res.json({
      message: "Login successful",
      role,
      username: user.username,
      userId: user._id,
      token,
    });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route to fetch user details (if needed)
app.get("/api/user/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ username: decoded.username, role: decoded.role });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/admin/addBook", async (req, res) => {
  try {
    const { title, author, copies, isbn } = req.body;

    // Validate input
    if (!title || !author || !copies || !isbn) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if book with same ISBN already exists
    const existingBook = await Book.findOne({ isbn });
    if (existingBook) {
      return res
        .status(400)
        .json({ error: "A book with this ISBN already exists" });
    }

    // Create new book
    const newBook = new Book({
      title,
      author,
      copies: parseInt(copies),
      availableCopies: parseInt(copies),
      isbn,
    });

    await newBook.save();

    res.status(201).json({ message: "Book added successfully", book: newBook });
  } catch (error) {
    console.error("Error adding book:", error);
    res.status(500).json({ error: "Failed to add book" });
  }
});
app.post("/api/requests", async (req, res) => {
  try {
    const { studentId, bookId, days } = req.body;

    const book = await Book.findById(bookId);
    if (!book || book.availableCopies <= 0) {
      return res.status(400).json({ error: "Book not available" });
    }

    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + days);

    const newRequest = new Request({
      student: studentId,
      book: bookId,
      dueDate,
      status: "Pending",
    });

    await newRequest.save();
    res.status(201).json({ message: "Request submitted successfully!" });
  } catch (error) {
    res.status(500).json({ error: "Error processing request" });
  }
});

app.get("/api/requests", async (req, res) => {
  try {
    const requests = await Request.find()
      .populate("student", "username")
      .populate("book", "title");
    res.json(requests);
  } catch (error) {
    console.error("Error fetching requests:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/requests/:id", async (req, res) => {
  try {
    const { status } = req.body;
    if (!["Approved", "Rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const request = await Request.findById(req.params.id);
    if (!request) return res.status(404).json({ error: "Request not found" });

    if (status === "Approved") {
      const book = await Book.findById(request.book);
      if (!book || book.availableCopies <= 0) {
        return res.status(400).json({ error: "Book not available" });
      }
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + 14);

      // Update User's borrowedBooks array
      await User.findByIdAndUpdate(
        request.student._id,
        {
          $push: {
            borrowedBooks: {
              bookId: request.book._id,
              dueDate: dueDate,
              status: "Active",
            },
          },
        },
        { new: true }
      );

      book.availableCopies -= 1;
      await book.save();
    }

    request.status = status;
    await request.save();

    res.json({ message: "Request status updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error updating request" });
  }
});

// Book Routes
app.get("/api/books", async (req, res) => {
  try {
    const books = await Book.find({ availableCopies: { $gt: 0 } });
    res.json(books);
  } catch (error) {
    console.error("Error fetching books:", error);
    res.status(500).json({ error: "Server error" });
  }
});
app.get("/api/students", async (req, res) => {
  try {
    const students = await User.find(); // Fetch all students
    res.json(students);
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).json({ error: "Failed to fetch students" });
  }
});

app.put("/api/students/:id", async (req, res) => {
  try {
    const { username, email, status } = req.body;
    const studentId = req.params.id;

    const updatedStudent = await User.findByIdAndUpdate(
      studentId,
      { username, email, status },
      { new: true, runValidators: true }
    );

    if (!updatedStudent) {
      return res.status(404).json({ error: "Student not found" });
    }

    res.json({
      message: "Student updated successfully",
      student: updatedStudent,
    });
  } catch (error) {
    console.error("Error updating student:", error);
    res.status(500).json({ error: "Failed to update student" });
  }
});

app.delete("/api/students/:id", async (req, res) => {
  try {
    const studentId = req.params.id;
    const deletedStudent = await User.findByIdAndDelete(studentId);

    if (!deletedStudent) {
      return res.status(404).json({ error: "Student not found" });
    }

    res.json({ message: "Student deleted successfully" });
  } catch (error) {
    console.error("Error deleting student:", error);
    res.status(500).json({ error: "Failed to delete student" });
  }
});
//
app.get("/api/user/books", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]; // Extract token from header
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const decoded = jwt.verify(token, SECRET_KEY);
    const student = await User.findOne({ username: decoded.username }).populate(
      "borrowedBooks.bookId"
    );

    if (!student) {
      return res.status(404).json({ error: "User not found" });
    }

    const books = student.borrowedBooks.map((borrowedBook) => ({
      _id: borrowedBook.bookId._id,
      title: borrowedBook.bookId.title,
      author: borrowedBook.bookId.author,
      dueDate: borrowedBook.dueDate,
      status: borrowedBook.status,
    }));

    res.json(books);
  } catch (error) {
    console.error("Error fetching user books:", error);
    res.status(500).json({ error: "Failed to fetch books" });
  }
});
//
app.post("/api/user/updateBookStatus", async (req, res) => {
  try {
    const { bookId } = req.body;
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, SECRET_KEY);
    const student = await User.findOne({ username: decoded.username });

    if (!student) return res.status(404).json({ error: "User not found" });

    const borrowedBook = student.borrowedBooks.find(
      (book) => book.bookId.toString() === bookId
    );
    if (!borrowedBook)
      return res.status(404).json({ error: "Book not found in user's list" });

    const currentDate = new Date();
    if (
      borrowedBook.dueDate < currentDate &&
      borrowedBook.status !== "Expired"
    ) {
      // Mark as expired
      borrowedBook.status = "Expired";
      await student.save();

      // Increase available copies of the book
      await Book.findByIdAndUpdate(bookId, { $inc: { availableCopies: 1 } });

      return res.json({ message: "Book status updated to Expired" });
    }

    res.json({ message: "Book status unchanged" });
  } catch (error) {
    console.error("Error updating book status:", error);
    res.status(500).json({ error: "Failed to update book status" });
  }
});
app.get("/api/stats", async (req, res) => {
  try {
    const totalBooks = await Book.countDocuments();
    const totalStudents = await User.countDocuments();
    const pendingRequests = await Request.countDocuments({ status: "Pending" });

    // Calculate total dues (assuming dues are stored in a `dues` field inside User schema)
    const totalDuesResult = await User.aggregate([
      { $group: { _id: null, totalDues: { $sum: "$dues" } } },
    ]);
    const totalDues =
      totalDuesResult.length > 0 ? totalDuesResult[0].totalDues : 0;

    res.json({
      totalBooks,
      totalStudents,
      pendingRequests,
      totalDues,
    });
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ error: "Failed to fetch dashboard stats" });
  }
});
app.get("/stats/borrowing-trend", async (req, res) => {
  try {
    const trendData = await Borrowing.aggregate([
      {
        $group: {
          _id: { $month: "$borrowedAt" }, // Group by month
          borrowedCount: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    const booksData = await Book.aggregate([
      {
        $group: {
          _id: null,
          availableCount: { $sum: "$availableCopies" },
        },
      },
    ]);

    const labels = trendData.map((data) => `Month ${data._id}`);
    const borrowedCounts = trendData.map((data) => data.borrowedCount);
    const availableCounts = booksData.length ? [booksData[0].availableCount] : [];

    res.json({ labels, borrowedCounts, availableCounts });
  } catch (error) {
    console.error("Error fetching borrowing trend:", error);
    res.status(500).json({ error: "Failed to fetch borrowing trend data" });
  }
});

// Start the server
app.listen(3000, () => {
  console.log("Server is running on port http://localhost:3000");
});
