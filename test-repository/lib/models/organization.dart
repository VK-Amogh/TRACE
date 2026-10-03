class Organization {
  final String id;
  final String name;
  final String plan;

  Organization({required this.id, required this.name, required this.plan});

  Map<String, dynamic> toJson() => {'id': id, 'name': name, 'plan': plan};
}

class Invoice {
  final String id;
  final double totalAmount;
  final String status;
  final String customerId;

  Invoice({
    required this.id,
    required this.totalAmount,
    required this.status,
    required this.customerId,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'total_amount': totalAmount,
    'status': status,
    'customer_id': customerId,
  };
}
