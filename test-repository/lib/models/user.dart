class User {
  final String id;
  final String email;
  final String role;
  final bool isAdmin;
  final String tier;

  User({
    required this.id,
    required this.email,
    required this.role,
    required this.isAdmin,
    required this.tier,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'email': email,
    'role': role,
    'is_admin': isAdmin,
    'tier': tier,
  };

  factory User.fromJson(Map<String, dynamic> json) => User(
    id: json['id'] as String,
    email: json['email'] as String,
    role: json['role'] as String? ?? 'USER',
    isAdmin: json['is_admin'] as bool? ?? false,
    tier: json['tier'] as String? ?? 'FREE',
  );
}
