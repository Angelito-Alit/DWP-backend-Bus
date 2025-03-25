const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const mercadopago = require('mercadopago');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const SSE = require('express-sse');

dotenv.config();
mercadopago.configurations.setAccessToken(process.env.MP_ACCESS_TOKEN);

const app = express();



const sse = new SSE([], { 
  isSerialized: true 
});

app.use(cors({
  origin: "*",
  credentials: true
}));
app.use(bodyParser.json());

const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Conectado a MongoDB Atlas');
})
.catch(err => {
  console.error('Error de conexión a MongoDB Atlas:', err);
});


const userSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['usuario', 'administrador'], default: 'usuario' },
  last_login: { type: Date, default: Date.now },
  mfaEnabled: { type: Boolean, default: false },
  mfaSecret: { type: String, default: null },
  resetPasswordToken: { type: String, default: null },
  resetPasswordExpires: { type: Date, default: null }
});

const busSchema = new mongoose.Schema({
  numeroPlaca: { type: String, required: true, unique: true },
  numeroUnidad: { type: String, required: true, unique: true },
  capacidad: { type: Number, required: true },
  asientos: [{
    numero: Number,
    disponible: {
      type: Boolean,
      default: true
    }
  }],
  createdAt: { type: Date, default: Date.now }
});

const routeSchema = new mongoose.Schema({
  origen: { type: String, required: true },
  destino: { type: String, required: true },
  fecha: { type: Date, required: true },
  hora: { type: String, required: true },
  precio: { type: Number, required: true },
  bus: { type: mongoose.Schema.Types.ObjectId, ref: 'Bus', required: true },
  createdAt: { type: Date, default: Date.now }
});

const ticketSchema = new mongoose.Schema({
  usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  ruta: { type: mongoose.Schema.Types.ObjectId, ref: 'Route', required: true },
  asiento: { type: Number, required: true },
  codigo: { type: String, required: true, unique: true },
  estado: { type: String, enum: ['reservado', 'pagado', 'cancelado'], default: 'reservado' },
  fechaCompra: { type: Date, default: Date.now }
});

const notificationSchema = new mongoose.Schema({
  usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  mensaje: { type: String, required: true },
  tipo: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  visto: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Bus = mongoose.model('Bus', busSchema);
const Route = mongoose.model('Route', routeSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);
const Notification = mongoose.model('Notification', notificationSchema);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: {
    rejectUnauthorized: false  
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Acceso denegado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

app.get('/api/notifications/connect', authenticateToken, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  sse.init(req, res, { userId: req.user.userId });
  
  res.write(`data: ${JSON.stringify({ type: 'connection', message: 'Conexión establecida' })}\n\n`);
});

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ 
      usuario: req.user.userId,
      visto: false
    }).sort({ createdAt: -1 });
    
    res.status(200).json(notifications);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener notificaciones', error: error.message });
  }
});

const sendNotification = async (userId, mensaje, tipo) => {
  try {
    const newNotification = new Notification({
      usuario: userId,
      mensaje,
      tipo
    });
    
    await newNotification.save();
    sse.send(
      {
        _id: newNotification._id,
        mensaje: newNotification.mensaje,
        tipo: newNotification.tipo,
        createdAt: newNotification.createdAt
      },
      userId.toString()
    );
    
    return newNotification;
  } catch (error) {
    console.error('Error al enviar notificación:', error);
    return null;
  }
};

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, usuario: req.user.userId },
      { visto: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({ message: 'Notificación no encontrada' });
    }
    
    res.status(200).json({ message: 'Notificación marcada como leída', notification });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la notificación', error: error.message });
  }
});

app.post('/api/auth/setup-mfa', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    const secret = speakeasy.generateSecret({
      name: `BusSeatManager:${user.email}`
    });
    
    user.mfaSecret = secret.base32;
    await user.save();
    
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    
    res.status(200).json({
      message: 'Secret MFA generado correctamente',
      secret: secret.base32,
      qrCodeUrl
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al configurar MFA', error: error.message });
  }
});

app.post('/api/auth/verify-mfa', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!user.mfaSecret) {
      return res.status(400).json({ message: 'MFA no configurado para este usuario' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token
    });
    
    if (!verified) {
      return res.status(400).json({ message: 'Código inválido' });
    }
    
    user.mfaEnabled = true;
    await user.save();
    
    await sendNotification(
      user._id,
      'Autenticación de dos factores activada correctamente',
      'success'
    );
    
    res.status(200).json({ message: 'MFA activado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al verificar MFA', error: error.message });
  }
});

app.post('/api/auth/validate-mfa', async (req, res) => {
  try {
    const { email, token } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!user.mfaEnabled || !user.mfaSecret) {
      return res.status(400).json({ message: 'MFA no está habilitado para este usuario' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token
    });
    
    if (!verified) {
      return res.status(400).json({ message: 'Código MFA inválido' });
    }
    
    const jwtToken = jwt.sign(
      { userId: user._id, email: user.email, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    user.last_login = Date.now();
    await user.save();
    
    const userResponse = {
      id: user._id,
      nombre: user.nombre,
      email: user.email,
      role: user.role,
      mfaEnabled: true
    };
    
    await sendNotification(
      user._id,
      'Inicio de sesión exitoso',
      'success'
    );
    
    res.status(200).json({ 
      message: 'Inicio de sesión exitoso', 
      token: jwtToken, 
      user: userResponse 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    const resetPasswordExpires = Date.now() + 3600000;
    
    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpires = resetPasswordExpires;
    await user.save();
    
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    const mailOptions = {
      from: '"Bus Seat Manager" <2022371110@uteq.edu.mx>',
      to: user.email,
      subject: 'Recuperación de contraseña',
      html: `
        <h1>Recuperación de contraseña</h1>
        <p>Has solicitado restablecer tu contraseña.</p>
        <p>Haz clic en el siguiente enlace para continuar:</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Restablecer contraseña</a>
        <p>Este enlace expirará en 1 hora.</p>
        <p>Si no solicitaste este cambio, ignora este mensaje.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ 
      message: 'Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña' 
    });
  } catch (error) {
    console.error('Error en recuperación de contraseña:', error);
    res.status(500).json({ 
      message: 'Error al procesar la solicitud', 
      error: error.message 
    });
  }
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const { password } = req.body;
    const resetToken = req.params.token;
    
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        message: 'Token inválido o expirado' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();
    
    await sendNotification(
      user._id,
      'Tu contraseña ha sido restablecida correctamente',
      'success'
    );
    
    res.status(200).json({ 
      message: 'Contraseña restablecida correctamente' 
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al restablecer la contraseña', 
      error: error.message 
    });
  }
});

app.get('/api/notifications/connect-sse/:token', (req, res) => {
  const token = req.params.token;
  
  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido' });
    }
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    sse.init(req, res, { userId: decoded.userId });
    
    res.write(`data: ${JSON.stringify({ type: 'connection', message: 'Conexión establecida' })}\n\n`);
  });
});



app.post('/api/mercadopago/create-preference', authenticateToken, async (req, res) => {
  try {
    const { routeId, asientoNumero } = req.body;
    
    const route = await Route.findById(routeId).populate('bus');
    if (!route) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }
    const preference = {
      items: [
        {
          title: `Asiento ${asientoNumero} - ${route.origen} a ${route.destino}`,
          quantity: 1,
          unit_price: route.precio,
          currency_id: "MXN",
          description: `Fecha: ${new Date(route.fecha).toLocaleDateString()} - Hora: ${route.hora}`
        }
      ],
      back_urls: {
        success: `${process.env.FRONTEND_URL}/checkout/success`,
        failure: `${process.env.FRONTEND_URL}/checkout/failure`,
        pending: `${process.env.FRONTEND_URL}/checkout/pending`
      },
      auto_return: "approved",
      external_reference: `${req.user.userId}-${routeId}-${asientoNumero}`
    };
    const response = await mercadopago.preferences.create(preference);
    res.json({ 
      preferenceId: response.body.id,
      init_point: response.body.init_point
    });
  } catch (error) {
    console.error('Error al crear preferencia:', error);
    res.status(500).json({ error: 'Error al crear preferencia de pago' });
  }
});

app.post('/api/mercadopago/webhook', async (req, res) => {
  const { type, data } = req.body;
  if (type === 'payment') {
    try {
      const paymentId = data.id;
      const payment = await mercadopago.payment.findById(paymentId);
      
      if (payment.status === 200 && payment.body.status === 'approved') {
        const externalRef = payment.body.external_reference;
        const [userId, routeId, asientoNumero] = externalRef.split('-');
        
        const existingTicket = await Ticket.findOne({ 
          ruta: routeId, 
          asiento: asientoNumero, 
          estado: { $ne: 'cancelado' } 
        });
        
        if (existingTicket) {
          console.log('El asiento ya está ocupado');
          return res.status(200).end();
        }
        const codigo = `T-${userId.substr(-4)}-${routeId.substr(-4)}-${asientoNumero}-${Date.now().toString(36)}`;
        const newTicket = new Ticket({
          usuario: userId,
          ruta: routeId,
          asiento: asientoNumero,
          codigo,
          estado: 'pagado'
        });
        await newTicket.save();
        console.log('Boleto creado exitosamente:', newTicket);
        
        await sendNotification(
          userId,
          `¡Pago recibido! Tu boleto con código ${codigo} ha sido generado.`,
          'success'
        );
      }
    } catch (error) {
      console.error('Error procesando pago:', error);
    }
  }
  res.status(200).end();
});

app.get('/api/mercadopago/verify-payment/:payment_id', authenticateToken, async (req, res) => {
  try {
    const { payment_id } = req.params;
    const { routeId, asientoNumero } = req.query;
    
    const payment = await mercadopago.payment.findById(payment_id);
    
    if (payment.status === 200 && payment.body.status === 'approved') {
      const existingTicket = await Ticket.findOne({ 
        ruta: routeId, 
        asiento: asientoNumero, 
        estado: { $ne: 'cancelado' } 
      });
      
      if (existingTicket) {
        return res.status(200).json({ 
          success: true, 
          ticket: existingTicket,
          message: 'El boleto ya existe' 
        });
      }
      
      const codigo = `T-${req.user.userId.substr(-4)}-${routeId.substr(-4)}-${asientoNumero}-${Date.now().toString(36)}`;
      
      const newTicket = new Ticket({
        usuario: req.user.userId,
        ruta: routeId,
        asiento: asientoNumero,
        codigo,
        estado: 'pagado'
      });
      
      await newTicket.save();
      
      const populatedTicket = await Ticket.findById(newTicket._id)
        .populate('usuario', 'nombre email')
        .populate({
          path: 'ruta',
          populate: { path: 'bus', select: 'numeroPlaca numeroUnidad' }
        });
      
      return res.status(200).json({ 
        success: true, 
        ticket: populatedTicket,
        message: 'Boleto creado exitosamente' 
      });
    } else {
      return res.status(400).json({ 
        success: false, 
        message: 'El pago no fue aprobado' 
      });
    }
  } catch (error) {
    console.error('Error verificando pago:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error al verificar el pago', 
      error: error.message 
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('Datos recibidos:', req.body);
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    const newUser = new User({
      nombre: req.body.nombre,
      email: req.body.email,
      password: hashedPassword
    });
    
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error('Error de registro:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }
    if (user.mfaEnabled) {
      return res.status(200).json({ 
        requireMFA: true,
        email: user.email,
        message: 'Se requiere verificación MFA'
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    user.last_login = Date.now();
    await user.save();

    const userResponse = {
      id: user._id,
      nombre: user.nombre,
      email: user.email,
      role: user.role,
      mfaEnabled: false
    };
    await sendNotification(
      user._id,
      'Inicio de sesión exitoso',
      'success'
    );

    res.status(200).json({ 
      message: 'Inicio de sesión exitoso', 
      token, 
      user: userResponse 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/routes/:id', authenticateToken, async (req, res) => {
  try {
    const routeId = req.params.id;
    const route = await Route.findById(routeId)
      .populate('bus', 'numeroPlaca numeroUnidad capacidad');
    
    if (!route) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }
    
    res.status(200).json(route);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener la ruta', error: error.message });
  }
});

app.post('/api/buses', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden crear autobuses' });
    }

    const { numeroPlaca, numeroUnidad, capacidad } = req.body;

    const asientos = [];
    for (let i = 1; i <= capacidad; i++) {
      asientos.push({ numero: i, disponible: true });
    }

    const newBus = new Bus({
      numeroPlaca,
      numeroUnidad,
      capacidad,
      asientos
    });

    await newBus.save();
    res.status(201).json({ message: 'Autobús creado exitosamente', bus: newBus });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear el autobús', error: error.message });
  }
});

app.get('/api/buses', authenticateToken, async (req, res) => {
  try {
    const buses = await Bus.find();
    res.status(200).json(buses);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los autobuses', error: error.message });
  }
});

app.put('/api/buses/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden actualizar autobuses' });
    }

    const { numeroPlaca, numeroUnidad, capacidad } = req.body;
    const busId = req.params.id;

    const bus = await Bus.findById(busId);
    if (!bus) {
      return res.status(404).json({ message: 'Autobús no encontrado' });
    }

    bus.numeroPlaca = numeroPlaca;
    bus.numeroUnidad = numeroUnidad;
    
    if (capacidad !== bus.capacidad) {
      const asientos = [];
      for (let i = 1; i <= capacidad; i++) {
        asientos.push({ numero: i, disponible: true });
      }
      bus.capacidad = capacidad;
      bus.asientos = asientos;
    }

    await bus.save();
    res.status(200).json({ message: 'Autobús actualizado correctamente', bus });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el autobús', error: error.message });
  }
});

app.delete('/api/buses/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden eliminar autobuses' });
    }

    const busId = req.params.id;
    
    const routesUsingBus = await Route.findOne({ bus: busId });
    if (routesUsingBus) {
      return res.status(400).json({ message: 'No se puede eliminar este autobús porque está siendo utilizado en rutas' });
    }

    const result = await Bus.findByIdAndDelete(busId);
    if (!result) {
      return res.status(404).json({ message: 'Autobús no encontrado' });
    }

    res.status(200).json({ message: 'Autobús eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar el autobús', error: error.message });
  }
});

app.post('/api/routes', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden crear rutas' });
    }

    const { origen, destino, fecha, hora, precio, busId } = req.body;

    const bus = await Bus.findById(busId);
    if (!bus) {
      return res.status(404).json({ message: 'Autobús no encontrado' });
    }

    const newRoute = new Route({
      origen,
      destino,
      origen,
      destino,
      fecha,
      hora,
      precio,
      bus: busId
    });

    await newRoute.save();
    res.status(201).json({ message: 'Ruta creada exitosamente', route: newRoute });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear la ruta', error: error.message });
  }
});

app.put('/api/routes/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden actualizar rutas' });
    }

    const { origen, destino, fecha, hora, precio, busId } = req.body;
    const routeId = req.params.id;

    const route = await Route.findById(routeId);
    if (!route) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }

    const bus = await Bus.findById(busId);
    if (!bus) {
      return res.status(404).json({ message: 'Autobús no encontrado' });
    }

    route.origen = origen;
    route.destino = destino;
    route.fecha = fecha;
    route.hora = hora;
    route.precio = precio;
    route.bus = busId;

    await route.save();
    res.status(200).json({ message: 'Ruta actualizada correctamente', route });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la ruta', error: error.message });
  }
});

app.delete('/api/routes/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden eliminar rutas' });
    }

    const routeId = req.params.id;
    
    const ticketsUsingRoute = await Ticket.findOne({ ruta: routeId });
    if (ticketsUsingRoute) {
      return res.status(400).json({ message: 'No se puede eliminar esta ruta porque tiene boletos asociados' });
    }

    const result = await Route.findByIdAndDelete(routeId);
    if (!result) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }

    res.status(200).json({ message: 'Ruta eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar la ruta', error: error.message });
  }
});

app.get('/api/routes', async (req, res) => {
  try {
    const routes = await Route.find()
      .populate('bus', 'numeroPlaca numeroUnidad capacidad');
    res.status(200).json(routes);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener las rutas', error: error.message });
  }
});

app.get('/api/routes/:routeId/seats', async (req, res) => {
  try {
    const { routeId } = req.params;
    
    const route = await Route.findById(routeId).populate('bus');
    if (!route) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }
    
    const tickets = await Ticket.find({ 
      ruta: routeId, 
      estado: { $ne: 'cancelado' } 
    });
    
    const occupiedSeats = tickets.map(ticket => ticket.asiento);
    
    const availableSeats = route.bus.asientos.filter(
      seat => !occupiedSeats.includes(seat.numero)
    );
    
    res.status(200).json({
      total: route.bus.capacidad,
      occupied: occupiedSeats,
      available: availableSeats
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los asientos', error: error.message });
  }
});

app.post('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const { routeId, asientoNumero } = req.body;
    const route = await Route.findById(routeId);
    if (!route) {
      return res.status(404).json({ message: 'Ruta no encontrada' });
    }
    
    const existingTicket = await Ticket.findOne({ 
      ruta: routeId, 
      asiento: asientoNumero, 
      estado: { $ne: 'cancelado' } 
    });
    
    if (existingTicket) {
      return res.status(400).json({ message: 'El asiento ya está ocupado' });
    }
    
    const codigo = `T-${req.user.userId.substr(-4)}-${routeId.substr(-4)}-${asientoNumero}-${Date.now().toString(36)}`;
    
    const newTicket = new Ticket({
      usuario: req.user.userId,
      ruta: routeId,
      asiento: asientoNumero,
      codigo,
      estado: 'pagado' 
    });
    
    await newTicket.save();
    
    const populatedTicket = await Ticket.findById(newTicket._id)
      .populate('usuario', 'nombre email')
      .populate({
        path: 'ruta',
        populate: { path: 'bus', select: 'numeroPlaca numeroUnidad' }
      });
      
    await sendNotification(
      req.user.userId,
      `¡Boleto comprado exitosamente! Código: ${codigo}`,
      'success'
    );
    
    res.status(201).json({ 
      message: 'Boleto comprado exitosamente', 
      ticket: populatedTicket 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al comprar el boleto', error: error.message });
  }
});

app.get('/api/tickets/my', authenticateToken, async (req, res) => {
  try {
    const tickets = await Ticket.find({ usuario: req.user.userId })
      .populate({
        path: 'ruta',
        populate: { path: 'bus', select: 'numeroPlaca numeroUnidad' }
      });
      
    res.status(200).json(tickets);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los boletos', error: error.message });
  }
});

app.get('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Acceso denegado' });
    }
    
    const tickets = await Ticket.find()
      .populate('usuario', 'nombre email')
      .populate({
        path: 'ruta',
        populate: { path: 'bus', select: 'numeroPlaca numeroUnidad' }
      });
      
    res.status(200).json(tickets);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los boletos', error: error.message });
  }
});

app.delete('/api/tickets/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'administrador') {
      return res.status(403).json({ message: 'Solo los administradores pueden cancelar boletos' });
    }

    const ticketId = req.params.id;
    
    const ticket = await Ticket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: 'Boleto no encontrado' });
    }

    ticket.estado = 'cancelado';
    await ticket.save();

    res.status(200).json({ message: 'Boleto cancelado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al cancelar el boleto', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('API de Bus Seat Manager funcionando correctamente con MongoDB Atlas');
});


module.exports = app;