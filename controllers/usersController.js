// exports.adminLogin = (req, res) => {
//     res.render('account/adminLogin');
// };

exports.guestLogin = (req, res) => {
    res.render('account/questLogin');
};

exports.index = (req, res) => {
    res.render('account/index');
};

exports.register = (req, res) => {
    res.render('account/register');
};