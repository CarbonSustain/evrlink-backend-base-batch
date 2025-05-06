# Evrlink API Documentation

## Authentication

All API endpoints require authentication unless specifically noted. Authentication is done via JWT tokens that are sent in the `Authorization` header.

Example:
```
Authorization: Bearer <your_jwt_token>
```

## Gift Cards API

### Set Secret Key for Gift Card

Sets a secret key for a gift card to make it claimable with the secret key.

**Endpoint 1 (Recommended RESTful style)**:
```
POST /api/gift-cards/:id/set-secret
```

**Path Parameters**:
- `id`: The ID of the gift card

**Request Body**:
```json
{
  "secret": "your-secret-key"
}
```

**Endpoint 2 (Legacy style, for backward compatibility)**:
```
POST /api/gift-cards/set-secret
```

**Request Body**:
```json
{
  "giftCardId": "123",
  "secret": "your-secret-key"
}
```

**Endpoint 3 (Old legacy style, also supported)**:
```
POST /api/giftcard/set-secret
```

**Request Body**:
```json
{
  "giftCardId": "123",
  "secret": "your-secret-key"
}
```

**Response**:
```json
{
  "success": true,
  "id": "123",
  "isClaimable": true,
  "transactionHash": "0x123..." // Optional, only if blockchain is enabled
}
```

**Error Responses**:

- `400 Bad Request`: Missing required fields
- `404 Not Found`: Gift card not found
- `403 Unauthorized`: User does not own the gift card
- `500 Internal Server Error`: Server or blockchain error

### Claim Gift Card with Secret Key

Claims a gift card using a secret key.

**Endpoint**:
```
POST /api/gift-cards/:id/claim
```

**Path Parameters**:
- `id`: The ID of the gift card

**Request Body**:
```json
{
  "secret": "your-secret-key"
}
```

**Response**:
```json
{
  "success": true,
  "id": "123",
  "currentOwner": "0x123...",
  "isClaimable": false
}
```

**Error Responses**:

- `400 Bad Request`: Missing required fields or invalid secret
- `404 Not Found`: Gift card not found
- `500 Internal Server Error`: Server or blockchain error

## Frontend Implementation Examples

### Setting a Secret Key

```typescript
// Using the RESTful API
const setGiftCardSecret = async (giftCardId: string, secret: string): Promise<any> => {
  try {
    const response = await fetch(`/api/gift-cards/${giftCardId}/set-secret`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
      },
      body: JSON.stringify({ secret }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to set gift card secret');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error setting gift card secret:', error);
    throw error;
  }
};
```

### Claiming a Gift Card

```typescript
// Using the RESTful API
const claimGiftCard = async (giftCardId: string, secret: string): Promise<any> => {
  try {
    const response = await fetch(`/api/gift-cards/${giftCardId}/claim`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
      },
      body: JSON.stringify({ secret }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to claim gift card');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error claiming gift card:', error);
    throw error;
  }
};
``` 