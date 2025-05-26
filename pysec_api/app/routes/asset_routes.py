from flask import Blueprint, request, jsonify

from pysec_api.app.models import db, Asset, User # Assuming User might be needed for typing or future use
from pysec_api.app.routes.auth_routes import token_required # Adjusted import path

asset_bp = Blueprint('asset', __name__, url_prefix='/assets')

# Placeholder for routes
# (Will be implemented in subsequent steps of this subtask)


@asset_bp.route('', methods=['POST'])
@token_required
def create_asset(current_user: User):
    data = request.get_json()

    if not data or not data.get('name') or not data.get('url'):
        return jsonify({'message': 'Missing name or url for the asset'}), 400

    name = data.get('name')
    url = data.get('url')
    total_findings = data.get('total_findings', 0)
    critical_findings = data.get('critical_findings', 0)
    prioritized_findings = data.get('prioritized_findings', 0)

    # Basic validation for findings types if provided
    try:
        total_findings = int(total_findings)
        critical_findings = int(critical_findings)
        prioritized_findings = int(prioritized_findings)
        if not (total_findings >= 0 and critical_findings >= 0 and prioritized_findings >= 0):
            raise ValueError("Findings counts must be non-negative.")
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid type for findings counts, must be non-negative integers.'}), 400


    new_asset = Asset(
        name=name,
        url=url,
        owner_id=current_user.id,
        total_findings=total_findings,
        critical_findings=critical_findings,
        prioritized_findings=prioritized_findings
    )

    try:
        db.session.add(new_asset)
        db.session.commit()
        return jsonify({
            'id': new_asset.id,
            'name': new_asset.name,
            'url': new_asset.url,
            'owner_id': new_asset.owner_id,
            'total_findings': new_asset.total_findings,
            'critical_findings': new_asset.critical_findings,
            'prioritized_findings': new_asset.prioritized_findings,
            'created_at': new_asset.created_at.isoformat() if new_asset.created_at else None
        }), 201
    except Exception as e: # pragma: no cover
        db.session.rollback()
        return jsonify({'message': f'Failed to create asset: {str(e)}'}), 500


@asset_bp.route('', methods=['GET'])
@token_required
def get_assets(current_user: User):
    """
    Get all assets owned by the current user.
    """
    user_assets = Asset.query.filter_by(owner_id=current_user.id).all()
    
    assets_list = []
    for asset in user_assets:
        assets_list.append({
            'id': asset.id,
            'name': asset.name,
            'url': asset.url,
            'owner_id': asset.owner_id,
            'total_findings': asset.total_findings,
            'critical_findings': asset.critical_findings,
            'prioritized_findings': asset.prioritized_findings,
            'created_at': asset.created_at.isoformat() if asset.created_at else None
        })
        
    return jsonify(assets_list), 200


@asset_bp.route('/<int:asset_id>', methods=['GET'])
@token_required
def get_asset_by_id(current_user: User, asset_id: int):
    """
    Get a specific asset by its ID.
    Ensures the asset is owned by the current user.
    """
    asset = Asset.query.get_or_404(asset_id)
    
    if asset.owner_id != current_user.id:
        return jsonify({'message': 'Forbidden: You do not own this asset'}), 403
        
    return jsonify({
        'id': asset.id,
        'name': asset.name,
        'url': asset.url,
        'owner_id': asset.owner_id,
        'total_findings': asset.total_findings,
        'critical_findings': asset.critical_findings,
        'prioritized_findings': asset.prioritized_findings,
        'created_at': asset.created_at.isoformat() if asset.created_at else None
    }), 200


@asset_bp.route('/<int:asset_id>', methods=['PUT'])
@token_required
def update_asset(current_user: User, asset_id: int):
    """
    Update a specific asset by its ID.
    Ensures the asset is owned by the current user.
    """
    asset = Asset.query.get_or_404(asset_id)
    
    if asset.owner_id != current_user.id:
        return jsonify({'message': 'Forbidden: You do not own this asset'}), 403
        
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    updated = False
    if 'name' in data:
        if not isinstance(data['name'], str) or not data['name'].strip():
            return jsonify({'message': 'Asset name must be a non-empty string'}), 400
        asset.name = data['name']
        updated = True
    if 'url' in data:
        if not isinstance(data['url'], str) or not data['url'].strip(): # Basic URL validation
            return jsonify({'message': 'Asset URL must be a non-empty string'}), 400
        asset.url = data['url']
        updated = True
    
    # Update findings counts, ensuring they are valid integers if provided
    for field in ['total_findings', 'critical_findings', 'prioritized_findings']:
        if field in data:
            try:
                value = int(data[field])
                if value < 0:
                    return jsonify({'message': f'{field.replace("_", " ").capitalize()} must be non-negative.'}), 400
                setattr(asset, field, value)
                updated = True
            except (ValueError, TypeError):
                return jsonify({'message': f'Invalid type for {field.replace("_", " ")}, must be an integer.'}), 400

    if updated:
        try:
            db.session.commit()
            return jsonify({
                'id': asset.id,
                'name': asset.name,
                'url': asset.url,
                'owner_id': asset.owner_id,
                'total_findings': asset.total_findings,
                'critical_findings': asset.critical_findings,
                'prioritized_findings': asset.prioritized_findings,
                'created_at': asset.created_at.isoformat() if asset.created_at else None
            }), 200
        except Exception as e: # pragma: no cover
            db.session.rollback()
            return jsonify({'message': f'Failed to update asset: {str(e)}'}), 500
    else:
        # Return current state if no recognized fields were updated or no data for update
        return jsonify({
            'id': asset.id,
            'name': asset.name,
            'url': asset.url,
            'owner_id': asset.owner_id,
            'total_findings': asset.total_findings,
            'critical_findings': asset.critical_findings,
            'prioritized_findings': asset.prioritized_findings,
            'created_at': asset.created_at.isoformat() if asset.created_at else None
        }), 200 # Or a 304 Not Modified, but 200 with current data is also common


@asset_bp.route('/<int:asset_id>', methods=['DELETE'])
@token_required
def delete_asset(current_user: User, asset_id: int):
    """
    Delete a specific asset by its ID.
    Ensures the asset is owned by the current user.
    """
    asset = Asset.query.get_or_404(asset_id)
    
    if asset.owner_id != current_user.id:
        return jsonify({'message': 'Forbidden: You do not own this asset'}), 403
        
    try:
        db.session.delete(asset)
        db.session.commit()
        # return jsonify({'message': 'Asset deleted successfully'}), 200
        return '', 204 # No Content is often preferred for DELETE success
    except Exception as e: # pragma: no cover
        db.session.rollback()
        return jsonify({'message': f'Failed to delete asset: {str(e)}'}), 500
