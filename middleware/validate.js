const { body, param, query, validationResult } = require('express-validator');

const validate = {
  user: [
    body('username').isString().trim().notEmpty().withMessage('Username is required'),
    body('password').isString().trim().notEmpty().withMessage('Password is required'),
  ],
  board: [
    body('name').isString().trim().notEmpty().withMessage('Board name is required'),
    body('description').isString().trim().notEmpty().withMessage('Description is required'),
  ],
  thread: [
    body('title').isString().trim().notEmpty().withMessage('Thread title is required'),
    body('content').isString().trim().notEmpty().withMessage('Post content is required'),
    param('boardId').isMongoId().withMessage('Invalid board ID'),
  ],
  post: [
    body('content').isString().trim().notEmpty().withMessage('Post content is required'),
    param('threadId').isMongoId().withMessage('Invalid thread ID'),
  ],
  report: [
    body('reason').isString().trim().notEmpty().withMessage('Reason is required'),
    param('postId').isMongoId().withMessage('Invalid post ID'),
  ],
  assignModerator: [
    body('userId').isMongoId().withMessage('Invalid user ID'),
    param('boardId').isMongoId().withMessage('Invalid board ID'),
  ],
  deletePost: [
    param('postId').isMongoId().withMessage('Invalid post ID'),
  ],
  pagination: [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  ],
};

const validateResult = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

module.exports = { validate, validateResult };